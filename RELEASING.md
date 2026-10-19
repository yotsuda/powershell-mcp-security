# Releasing

The skill (`powershell-mcp-security`) and the PowerShell module (`NetworkSecurityAudit`) share one version number and are released together, from one tag.

## How it fits together

- **`main`** is where work lands. Pushing to `main` does **not** reach users.
- **`release`** is what users get. The marketplace ([yotsuda/powershell-mcp-plugins](https://github.com/yotsuda/powershell-mcp-plugins)) serves the plugin from this branch, and so does the Claude plugin directory. It only ever points at a tagged commit.
- **A tag `vX.Y.Z`** on a commit of `main` releases X.Y.Z: the release workflow publishes the module to the PowerShell Gallery and moves `release` to that commit.

So the module bundled in a released plugin is always byte-for-byte the module on the Gallery with the same version, and a published version number never stands for two different contents.

## Steps

1. **Decide that the changes on `main` are ready.** A Gallery version can never be replaced, only unlisted. Batch fixes; don't release per fix.
2. **Set the version** X.Y.Z (semantic versioning: patch for fixes, minor for new checks or functions) in both places, in one commit:
   - `.claude-plugin/plugin.json` → `"version": "X.Y.Z"`
   - `module/NetworkSecurityAudit/NetworkSecurityAudit.psd1` → `ModuleVersion = 'X.Y.Z'`, and `ReleaseNotes` — what changed since the last release, newest first. It becomes the GitHub Release text.
3. **Push to `main`** and wait for **Module tests** to pass (Windows and Linux).
4. **Tag that commit and push the tag:**
   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
5. **Watch the Release workflow:** `gh run watch -R yotsuda/powershell-mcp-security` (or the Actions tab).
6. **Check the result:**
   - `Find-PSResource NetworkSecurityAudit -Version X.Y.Z -Repository PSGallery` finds it.
   - `git ls-remote origin release` points at the tagged commit.
   - The GitHub Release `vX.Y.Z` exists.
   - On a machine with the plugin: `claude plugin marketplace update powershell-mcp`, then `claude plugin update powershell-mcp-security@powershell-mcp` reports X.Y.Z.
7. **Claude plugin directory:** new commits on `release` are picked up about every 6 hours (or use **Check for new commits** on the plugin's page). Auto-publish is off, so select **Publish** for the new version once it passes its checks.

## What the workflow checks before publishing

`.github/workflows/release.yml` stops before anything irreversible if:

- `plugin.json` `version` or the manifest's `ModuleVersion` is not the tag's version;
- the tag is not on a commit of `main`;
- `ReleaseNotes` is empty;
- the version is already on the Gallery;
- `release` has commits that are not in the tag (it must fast-forward);
- the tests fail, or the assembled package does not import or `Test-NsaTcpPort` does not work.

Then it publishes to the Gallery, fast-forwards `release` to the tag and creates the GitHub Release, in that order.

## When something fails

- **Before "Publish to the PowerShell Gallery"**: nothing is released. Fix it on `main`, delete the tag (`git tag -d vX.Y.Z; git push origin :refs/tags/vX.Y.Z`), and tag the new commit.
- **"Publish" failed with 403**: the API key is invalid, expired, or not allowed to push `NetworkSecurityAudit`. Create a key on powershellgallery.com (scope: push new packages and versions; glob: `NetworkSecurityAudit`), set it with `gh secret set PSGALLERY_API_KEY -R yotsuda/powershell-mcp-security`, and re-run the failed job (`gh run rerun <run id> --failed`).
- **After "Publish" succeeded but a later step failed**: the version is on the Gallery, so do **not** re-run the whole workflow (it would stop at "already on the Gallery"). Finish by hand:
  ```
  git push origin vX.Y.Z^{commit}:refs/heads/release
  gh release create vX.Y.Z --title vX.Y.Z --notes "<the ReleaseNotes>"
  ```
- **A released version is broken**: release a fixed X.Y.(Z+1). If it must not be installed, unlist X.Y.Z on the Gallery as well.

## One-time setup (already done)

- Repository secret `PSGALLERY_API_KEY`: a Gallery API key allowed to push `NetworkSecurityAudit`.
- The marketplace entry's source has `"ref": "release"`.
- The plugin directory submission tracks the `release` branch.
