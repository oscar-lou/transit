"""Tests for the DataSource abstraction (file I/O seam) - verifies
LocalDataSource behaves identically to the pre-refactor direct os.listdir()/
open() code, so the abstraction itself is verified, not just trusted.
"""
import consolidate_noncompliant as cnc


def test_exists_true_when_directory_present(tmp_path):
    assert cnc.LocalDataSource(str(tmp_path)).exists() is True


def test_exists_false_when_directory_absent(tmp_path):
    assert cnc.LocalDataSource(str(tmp_path / "nonexistent")).exists() is False


def test_list_files_empty_when_directory_absent(tmp_path):
    assert cnc.LocalDataSource(str(tmp_path / "nonexistent")).list_files() == []


def test_list_files_returns_sorted_names_no_directory_component(tmp_path):
    (tmp_path / "Zeta.xlsx").write_bytes(b"z")
    (tmp_path / "Alpha.xlsx").write_bytes(b"a")
    (tmp_path / "Mid.csv").write_bytes(b"m")
    assert cnc.LocalDataSource(str(tmp_path)).list_files() == \
        ["Alpha.xlsx", "Mid.csv", "Zeta.xlsx"]


def test_read_file_returns_exact_bytes(tmp_path):
    (tmp_path / "data.csv").write_bytes(b"col1,col2\r\nval1,val2\r\n")
    assert cnc.LocalDataSource(str(tmp_path)).read_file("data.csv") == \
        b"col1,col2\r\nval1,val2\r\n"


def test_read_file_round_trips_binary_xlsx_content(tmp_path):
    """Not just text - a real xlsx (zip/binary) must survive read_file()
    byte-for-byte, since _read_xlsx_rows() feeds this straight into
    openpyxl.load_workbook(io.BytesIO(...))."""
    import openpyxl
    path = tmp_path / "book.xlsx"
    wb = openpyxl.Workbook()
    wb.active.append(["a", "b"])
    wb.save(path)
    on_disk = path.read_bytes()
    assert cnc.LocalDataSource(str(tmp_path)).read_file("book.xlsx") == on_disk


def test_get_data_source_reflects_current_data_dir(data_dir):
    """_get_data_source() must not cache - it should reflect whatever
    DATA_DIR is set to AT CALL TIME, since tests (and real config changes)
    redirect DATA_DIR at runtime, not at import time."""
    source = cnc._get_data_source()
    assert isinstance(source, cnc.LocalDataSource)
    assert source.directory == str(data_dir)


def test_local_data_source_matches_pre_refactor_behavior_end_to_end(tmp_path, monkeypatch):
    """Same real scenario as test_file_matching.py's matching tests, but
    asserting the DataSource layer itself produces the same list_files()/
    read_file() results a direct os.listdir()/open() would have - the seam
    is transparent, not just 'tests still pass'."""
    import os as os_module
    (tmp_path / "AIAGO_Workstation_CS.xlsx").write_bytes(b"fake xlsx bytes")
    (tmp_path / "notes.txt").write_bytes(b"ignored by find_dataset, but still listed")

    source = cnc.LocalDataSource(str(tmp_path))
    assert source.list_files() == sorted(os_module.listdir(tmp_path))
    assert source.read_file("AIAGO_Workstation_CS.xlsx") == b"fake xlsx bytes"
