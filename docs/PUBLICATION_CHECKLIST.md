# Publication review — owner decisions remain

Prepared package; nothing has been uploaded publicly.

1. Confirm creator display name Sebastian Weerakkody and rights to the included code/docs.
2. MIT licence approved by the owner on 22 October 2026. Root LICENSE and CITATION.cff updated; propagate MIT to the separate Zenodo and Hugging Face packages before publication.
3. Review the privacy/redaction report and selected evidence. Confirm that event/run IDs and historical model outputs may be public.
4. GitHub repository selected: https://github.com/swaiproject/AISA (private at verification). Hugging Face account and Space remain to be selected.
5. Run the offline verification in Ubuntu VMware and retain the result. Review the packaging verification's environment and limitations.
6. Visually review the Space in a browser; only JavaScript DOM interaction was tested here because browser installation failed. Set the actual publication date; create the GitHub release/tag only after approval. Candidate identity is 1.0.0-rc1, not a claim that the original core became v1.0.
7. Reserve the Zenodo DOI and insert actual repository/DOI links into citation metadata and the Space README. Rebuild hashes after any changes, verify, then publish.
8. Preserve the internal historical archive unchanged. Upload the clean public artifacts, not the complete internal backup.

GitHub: extract this directory into the chosen repository; retain file structure. Review before pushing. Add the active licence and public metadata, then tag the approved release.
Zenodo: upload the coordinated archive or archive the approved GitHub release. Use the proposed metadata worksheet; do not publish an unapproved licence or invent a DOI.
Hugging Face: create a Static Space; upload the separate huggingface directory's contents, not its enclosing folder. The page is a recorded-evidence walkthrough; it does not run Python or call providers. Set the active licence in README metadata after approval.

Official platform references checked 19 October 2026:
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files
- https://help.zenodo.org/docs/github/archive-software/github-upload/
- https://help.zenodo.org/docs/deposit/create-new-upload/
- https://huggingface.co/docs/hub/spaces-sdks-static

GitHub download verification on 22 October 2026: all 126 original package files matched byte for byte; the only additional file was .gitattributes containing `* -text`. Subsequent licence and documentation edits are recorded in docs/LICENSE-AND-FEEDBACK-UPDATE.md.
