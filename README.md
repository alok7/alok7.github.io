# Wallstrat

Static GitHub Pages site for https://wallstrat.com. Publish the repository root
from `master`; preserve `CNAME` and `.nojekyll`. No build step, package install,
external font, analytics, framework or CDN is required.

The site presents historical strategy research, not a live investment track record.
Dates, accounting differences and research limitations are part of the published
content. Do not replace them with unqualified performance claims.

## Updating the evidence

`assets/evidence.json` identifies the source artifacts and SHA-256 hashes.
`assets/performance.csv` contains the summary. `assets/performance.js` contains
aggregate chart observations, mirrored in `assets/equity.csv`. Charts use these
observations, not an illustrative or smoothed curve. Source trading records,
private books and credentials must not be added to this repository.

When results change, update both the static table/headline and chart data, dates,
disclosures, social metadata and sitemap `lastmod`. Verify returns, drawdowns,
trade counts, metric conventions and provenance before publication. In particular,
the strangle archive books P&L at expiry and does not validate its corrected live
implementation.

## Search visibility

- The homepage has a canonical HTTPS URL, semantic HTML, descriptive title and
  meta description, WebSite/WebPage JSON-LD, social image metadata, robots.txt
  and a sitemap.
- After publication, verify the `wallstrat.com` domain in Google Search Console
  and Bing Webmaster Tools, submit `https://wallstrat.com/sitemap.xml`, and inspect
  the homepage URL. Verification requires the domain owner's account or DNS access.
- Check actual deployed Core Web Vitals and indexing coverage. Local browser
  tests and a small payload do not establish field performance or search ranking.
- Removed legacy URLs return the custom 404 page. Do not redirect unrelated old
  research pages to the homepage merely to conceal missing content.

See Google's [SEO starter guide](https://developers.google.com/search/docs/fundamentals/seo-starter-guide)
and [sitemap guidance](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap).

## Repository size

This replacement is designed for one new root commit, without an old parent tree.
Normal subsequent updates can be ordinary commits. Avoid repeatedly rewriting
history. Keep large datasets and generated run archives outside the website repo.

A history reset removes old commits from the new branch ancestry; GitHub may
retain unreachable objects/cached commits until its own cleanup. It is not a
guaranteed permanent purge of every remote copy.
