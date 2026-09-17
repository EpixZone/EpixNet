# ark-relations diagnostic-layer compatibility patch

Based on crates.io `ark-relations` 0.5.1, upstream
<https://github.com/arkworks-rs/snark>. The registry archive SHA-256 is
`ec46ddc93e7af44bcab5230937635b06fb5744464dd6a7e7b083e80ebd274384`.
Upstream license files and commit provenance are retained here.

The current RLN 3 dependency graph uses arkworks 0.5. Its `std` feature pulls
`tracing-subscriber` 0.2, affected by
[GHSA-xwfj-jgwm-7wp5](https://github.com/tokio-rs/tracing/security/advisories/GHSA-xwfj-jgwm-7wp5).
The published ark-relations 0.6 release uses the new arkworks 0.6 APIs throughout;
changing the entire proof stack is unnecessary for this logging fix.

This patch changes only the diagnostic integration:

- Require `tracing-subscriber >=0.3.20, <0.4` and explicitly enable its registry.
- Implement `Layer::on_new_span`, the 0.3 callback replacing `new_span`.
- Update the diagnostic API documentation links.

Constraint arithmetic, proof serialization and RLN parameters remain upstream
0.5.1. The root workspace patch applies to all consumers, eliminating the 0.2
subscriber from the application lockfile. Remove this vendor patch when an
upstream compatible release is available or the whole RLN stack is upgraded.
