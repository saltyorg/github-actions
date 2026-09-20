# Agent guidance

## Release completion

- Read the release policy in `README.md` before changing release instructions,
  creating or pushing a tag.
- Establish the upstream published releases from the remote, then agree the
  release version and exact commit with the user. Local tags and branch tips
  do not establish published versions.
- For an authorized release, run the repository's required validation on the
  exact commit, push the agreed tag, and verify that the remote tag resolves to
  that commit and the release workflow publishes successfully. Do not stop at
  a local tag or call the release complete before publication is verified.
- Tag creation, tag pushing, and release publication must be within the user's
  authorization. Complete steps already authorized without asking again; if
  authorization or validation is missing, report the specific incomplete step.
- Preserve existing tags. Changing an existing tag requires separate explicit
  authorization.
