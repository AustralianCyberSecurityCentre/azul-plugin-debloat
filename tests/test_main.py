"""Test cases for plugin output."""

from azul_runner import (
    FV,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)

from azul_plugin_debloat.main import AzulPluginDebloat


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginDebloat

    def test_malformed_pe(self):
        """Malformed PE or non-PE files opt out because it can't be processed."""
        result = self.do_execution(data_in=[("content", b"random text I guess")], verify_input_content=False)
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="not_pe",
                    message="The provided file is not a pe file and is being ignored.",
                )
            ),
        )

    def test_bloated_pe(self):
        """Valid PE is debloated."""
        data = self.load_test_file_bytes(
            "80c8984124c10649e5d4f64d1204d6375ee8a95203e0c91da3763d80381e1f93", "Malicious Windows 32EXE."
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="80c8984124c10649e5d4f64d1204d6375ee8a95203e0c91da3763d80381e1f93",
                        features={"bloat_removed": [FV(47810)], "bloat_tactic": [FV("Bloat in PE resources")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="80c8984124c10649e5d4f64d1204d6375ee8a95203e0c91da3763d80381e1f93",
                        ),
                        entity_type="binary",
                        entity_id="8f341ecc017430a13367234aeff62bba9e71a252a15be8a6e93eb53bce20a581",
                        relationship={"action": "de-bloated"},
                        data=[
                            EventData(
                                hash="8f341ecc017430a13367234aeff62bba9e71a252a15be8a6e93eb53bce20a581",
                                label="content",
                            )
                        ],
                    ),
                ],
                data={"8f341ecc017430a13367234aeff62bba9e71a252a15be8a6e93eb53bce20a581": b""},
            ),
        )

    def test_flat_pe(self):
        """PE that has no bloat Completes with no bloat found"""
        data = self.load_test_file_bytes(
            "702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
            "Benign WIN32 EXE, python library executable python_mcp.exe",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
                        features={"bloat_tactic": [FV("No Bloat")]},
                    )
                ],
            ),
        )
