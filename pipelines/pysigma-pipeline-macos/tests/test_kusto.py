"""Sentinel / Defender XDR (Kusto) conversion of macOS process_creation.

NOTE: microsoft_xdr_pipeline is product-agnostic. macos, windows and no-product rules
convert identically through the generic Windows-schema category mapping (file_event ->
DeviceFileEvents too). This proves the query shape only, not that Defender populates
these tables for macOS.
"""
from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline


def convert(field: str) -> str:
    rule = f"""
title: T
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        {field}|endswith: /{'curl' if field == 'Image' else 'bash'}
    condition: selection
"""
    return KustoBackend(processing_pipeline=microsoft_xdr_pipeline()).convert(SigmaCollection.from_yaml(rule))[0]


def test_kusto_macos_process_creation():
    assert convert("Image") == 'DeviceProcessEvents\n| where FolderPath endswith "/curl"'


def test_kusto_macos_parent_image():
    assert convert("ParentImage") == 'DeviceProcessEvents\n| where InitiatingProcessFolderPath endswith "/bash"'
