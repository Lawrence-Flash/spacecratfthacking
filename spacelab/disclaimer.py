"""Shared wording so every output says what this lab is."""

DISCLAIMER = (
    "Simulated teaching data only. SpaceLab does not transmit radio, "
    "connect to ground stations, or provide access to any real spacecraft."
)

LAB_KEY_ID = "LAB-TEACHING-KEY"
# Ships with the lab so the detector can recompute tags. A mission MAC key
# does not belong in the same repository as the ops tools. See checklist SL-04.
LAB_MAC_KEY = b"spacelab-fs1-lab-teaching-key"
MAC_ALGORITHM = "HMAC-SHA256-128"
