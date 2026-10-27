# Publishing the public source

The publication command uses an explicit allowlist. It includes application source, development tests, synthetic example files, documentation, and `docs/screenshots/overview.png`. It excludes `.fieldmate/`, original Burp projects, HAR files, databases, environment files, reports, captures, generated binaries, archives, and all other images.

From the project directory:

```sh
python3 -m unittest discover -s tests -v
python3 tools/prepare_publication.py --output ../fieldmate-github.zip
```

The command checks selected text files for common credential patterns and personal home paths, rejects linked source files, and writes a SHA-256 manifest into the ZIP. Matches report only file, line number, and category. This is a best-effort scan; inspect additions before each publication. Credential-URL exceptions cover two exact synthetic fixture values in one test file, not the entire file.

The README screenshot is generated from a disposable practice-lab instance in `tests/browser.cjs`. It contains synthetic targets/accounts only and was inspected visually. Never replace it with a screenshot from a real engagement.

## GitHub

Create an empty **public** GitHub repository under the intended account or organization. Upload the contents of the clean ZIP, or push the prepared local source repository after authenticating to GitHub. Do not upload the working directory wholesale. A fresh clone starts without your existing app data or inference configuration.

For a prepared local repository, replace `OWNER/REPOSITORY` with the actual destination:

```sh
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

The prepared initial commit uses a neutral project author. Configure your preferred GitHub noreply identity before later commits if you want account attribution without publishing your personal email.

Review `git diff --cached --stat` and the actual staged patch before committing. `.gitignore` helps prevent mistakes but cannot remove already tracked secrets or inspect arbitrary files. If a credential is ever published, revoke/rotate it; deleting the file does not remove it from Git history.

Generated JARs are excluded from the source repository. Build the companion from `integrations/burp` using `gradle jar`; publish a rebuilt binary as a separate release asset only after verification. No open-source license has been selected for this project.
