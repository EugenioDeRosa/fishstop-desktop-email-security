# Public email provider domains

`public_email_provider_domains.txt` is a vendored snapshot of the MIT-licensed
[Validemailchecker free email provider domains](https://github.com/Validemailchecker/free-email-provider-domains)
dataset. It is used only to exclude shared mailbox-provider domains from OTX
on-demand queries. FishStop submits the sender domain exactly as it appears in
the address and does not derive or test its parent domain.

The upstream dataset is rebuilt weekly. Replace this snapshot from the upstream
`data/domains.txt` file after validating that it contains one normalized domain
per line. The upstream MIT license is retained alongside the data.
