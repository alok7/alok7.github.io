# Wallstrat

Single-page strategy dashboard at https://wallstrat.com. GitHub Pages serves the
root of `master`. Preserve `CNAME` and `.nojekyll`. No build server, external
fonts, analytics or JavaScript dependencies are required.

The page contains three strategies, each with separate Live and Backtest views.
VPT's live view uses the manually executed account; missing live books are shown
explicitly. Historical positions are labelled with the backtest endpoint.

## Refresh

Run from the private research checkout, after the trading run has saved its book:

```sh
venv/bin/python tools/build_wallstrat.py
venv/bin/python tools/build_wallstrat.py --commit
venv/bin/python tools/build_wallstrat.py --push --message "Refresh strategy performance"
```

The first invocation clones this repository into `tools/wallstrat_site/`.
Subsequent invocations pull with `--ff-only` before applying generated outputs.
Default mode only generates; `--commit` commits locally; `--push` also pushes.
The tool preserves unrelated edits and never force-pushes or resets history.
Previously generated, unedited output can be safely rebuilt. `--offline` skips
synchronization for preview and cannot be combined with `--push`.

The source templates and explicit data mappings live in `tools/wallstrat/` in
the research checkout. Update the templates there, since generated files are
replaced on refresh. No broker access or trading occurs during publication.
The page is a dated snapshot, not a streaming feed; refresh after the book and
market cache have both been updated. No recurring job is installed automatically.

## Data

`assets/dashboard.json` is the public dataset, also packaged as a local script
for file-based previews. CSV downloads contain performance, chart observations
and positions. Public exports contain only selected financial fields: no broker
credentials, order identifiers, runtime state or private logs.

Live P&L includes estimated recorded fees. Open-position P&L includes remaining
entry fees; realised P&L includes allocated entry and exit fees. Charts replay
confirmed fills against cached daily closes, using recorded execution dates.
Capital flows are excluded from P&L; return uses a beginning-of-day flow
convention. The exporter refuses inconsistent cash, holdings, dates or missing
held-symbol prices. These are account-record reconstructions, not an audit.

Backtests retain their original periods and accounting. VPT and Leader Volume
use daily marks. Index Volatility is an exploratory expiry-booked archive with
a proxy futures hedge; it does not establish intraday drawdown or validate the
corrected execution code. Backtest Sharpe uses a 6.5% annual risk-free rate.

## Search

The page has static strategy headings, metrics and charts, an HTTPS canonical,
descriptive metadata, structured data, robots.txt and a sitemap. Submit
`https://wallstrat.com/sitemap.xml` in the domain owner's Google Search Console
and Bing Webmaster Tools accounts. Indexing and ranking are not guaranteed.
