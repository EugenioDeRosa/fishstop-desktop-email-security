# Public email provider domains

`public_email_provider_domains.txt` is a vendored snapshot of the MIT-licensed
[Validemailchecker free email provider domains](https://github.com/Validemailchecker/free-email-provider-domains)
dataset. It is used only to classify domain-level OTX matches on shared mailbox
services as contextual evidence. Exact email-address indicators remain strong
threat matches.

The upstream dataset is rebuilt weekly. Replace this snapshot from the upstream
`data/domains.txt` file after validating that it contains one normalized domain
per line. The upstream MIT license is retained alongside the data.
