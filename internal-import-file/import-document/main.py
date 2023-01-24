# -*- coding: utf-8 -*-
"""OpenCTI ReportImporter connector main module."""

from src import ImportDocument

if __name__ == "__main__":
    connector = ImportDocument()
    connector.start()
