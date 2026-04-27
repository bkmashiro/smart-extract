# Manual Test Checklist: Delete After Extract Feature

## Prerequisites
- Windows machine with 7-Zip installed
- `smart-extract.exe` built and placed in a test directory
- `config.yaml` alongside the exe
- Some test `.zip` and `.7z` files (with and without passwords)

## Test Cases

### 1. First-time extraction — dialog appears
- [ ] Delete `learned.yaml` (or ensure `preferences` key is absent)
- [ ] Right-click a `.zip` file → Smart Extract
- [ ] Extraction completes successfully
- [ ] A zenity dialog appears: "解压完成！是否删除原始压缩包？"
- [ ] Dialog has buttons: "是，删除" and "否，保留"

### 2. Choose "是，删除" — archive is deleted
- [ ] In the dialog from test 1, click "是，删除"
- [ ] The original `.zip` file is deleted
- [ ] The extracted folder remains with correct contents
- [ ] `learned.yaml` now contains:
  ```yaml
  preferences:
    delete_after_extract: true
    delete_preference_set: true
  ```

### 3. Subsequent extraction — no dialog, auto-delete
- [ ] Extract another archive (with preference set to `true`)
- [ ] No dialog appears
- [ ] The archive is silently deleted after successful extraction
- [ ] Extracted contents are correct

### 4. Reset and choose "否，保留"
- [ ] Run `smart-extract.exe --reset-prefs`
- [ ] Confirm message: "偏好设置已重置"
- [ ] Extract an archive
- [ ] Dialog appears again
- [ ] Click "否，保留"
- [ ] The original archive is NOT deleted
- [ ] `learned.yaml` shows `delete_after_extract: false`

### 5. Subsequent extraction — no dialog, archive preserved
- [ ] Extract another archive (with preference set to `false`)
- [ ] No dialog appears
- [ ] The archive is NOT deleted

### 6. Failed extraction — no deletion
- [ ] Use a password-protected archive with wrong passwords configured
- [ ] Let extraction fail
- [ ] The original archive must NOT be deleted
- [ ] No delete dialog should appear

### 7. Multi-part archive (.zip.001, .zip.002, ...)
- [ ] Create a multi-part zip (e.g., using 7z: `7z a -v10m archive.zip files/`)
- [ ] Set preference to delete (`delete_after_extract: true`)
- [ ] Extract `archive.zip.001`
- [ ] ALL parts (.001, .002, .003, ...) are deleted
- [ ] Extracted contents are correct

### 8. Batch extraction — per-file deletion
- [ ] Select multiple archives and extract them
- [ ] With delete preference set to `true`
- [ ] Each archive is deleted independently after its own successful extraction
- [ ] If one fails, only the failed archive is preserved; others are deleted

### 9. Nested archives — outer not deleted prematurely
- [ ] Create an archive containing another archive inside
- [ ] Extract with delete preference on
- [ ] Inner archive is extracted recursively
- [ ] Only after all nested extractions complete is the outer archive deleted

### 10. Permission error on delete — graceful warning
- [ ] Set an archive file to read-only (`attrib +R archive.zip`)
- [ ] Extract with delete preference on
- [ ] Extraction succeeds
- [ ] A warning is printed about the deletion failure
- [ ] The overall operation does NOT fail (exit code 0)

### 11. --reset-prefs flag
- [ ] Run `smart-extract.exe --reset-prefs`
- [ ] Output shows: "✓ 偏好设置已重置，下次解压时将重新询问。"
- [ ] `learned.yaml` preferences are cleared
- [ ] Next extraction shows the dialog again
