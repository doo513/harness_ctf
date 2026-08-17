from ctf_harness.tools.candidate_extract import FlagCandidateExtractor


def test_flag_candidate_extractor_dedupes_but_never_accepts() -> None:
    extractor = FlagCandidateExtractor()
    candidates = extractor.extract(
        "example flag{decoy} then flag{decoy} and CTF{other}",
        source_ref="artifact://fixture",
    )
    assert len(candidates) == 2
    descriptors = [item.descriptor() for item in candidates]
    assert all(item["accepted"] is False for item in descriptors)
    assert all(item["authority"] == "candidate_observation_only" for item in descriptors)
    assert all("candidate" not in item for item in descriptors)
