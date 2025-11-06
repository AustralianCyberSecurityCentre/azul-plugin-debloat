"""Debloat removes excess garbage from bloated executables."""

import os
import tempfile

import debloat
import debloat.processor
import pefile
from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)


class AzulPluginDebloat(BinaryPlugin):
    """Debloat removes excess garbage from bloated executables."""

    VERSION = "2025.06.11"
    SETTINGS = add_settings(
        # Must be at least 10MB exe to try and debloat
        filter_min_content_size=(int, 10 * 1024 * 1024),
        # Up to 10Gi files
        filter_max_content_size=(int, 10 * 1024 * 1024 * 1024),
        # Ignore this plugins output.
        filter_self=True,
        # Accept any windows executable or dll
        filter_data_types={"content": ["executable/windows/"]},
    )
    FEATURES = [
        Feature("bloat_tactic", desc="Bloat tactic found in the binary.", type=FeatureType.String),
        Feature(
            "bloat_removed",
            desc="Total bloated bytes removed from the binary.",
            type=FeatureType.Integer,
        ),
    ]

    def _ignore_debloat_logs(self, msg: str, *args, **kwargs):
        """Ignore debloat logs and just pass.

        Note args and kwargs are end, flush etc expected to be used on print.
        """
        pass

    def execute(self, job: Job):
        """Run the plugin and debloat PEs."""
        file_ref = job.get_data()
        try:
            with pefile.PE(file_ref.get_filepath(), fast_load=True) as pe:
                with tempfile.NamedTemporaryFile() as out_file:
                    result_code = debloat.processor.process_pe(
                        pe,
                        out_path=str(out_file.name),
                        last_ditch_processing=False,
                        cert_preservation=False,
                        log_message=self._ignore_debloat_logs,
                    )

                    # Complete empty because no bloat could be removed.
                    if result_code == 0:
                        # Better default message for no bloat
                        self.add_feature_values("bloat_tactic", "No Bloat")
                        return
                    result_message = debloat.processor.RESULT_CODES[result_code]
                    self.add_feature_values("bloat_tactic", result_message)

                    out_file.seek(0)
                    self.add_child_with_data_file({"action": "de-bloated"}, out_file)

                    temp_file_stats = os.stat(out_file.name)
                    self.add_feature_values("bloat_removed", file_ref.file_info.size - temp_file_stats.st_size)

        except pefile.PEFormatError:
            return State(State.Label.OPT_OUT, "not_pe", "The provided file is not a pe file and is being ignored.")


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginDebloat)


if __name__ == "__main__":
    main()
