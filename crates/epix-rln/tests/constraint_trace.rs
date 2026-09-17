//! The patched arkworks diagnostics must capture spans using subscriber 0.3.
use ark_relations::r1cs::{ConstraintLayer, ConstraintTrace};
use tracing_subscriber::prelude::*;

#[test]
fn constraint_trace_preserves_nested_spans_on_subscriber_03() {
    let subscriber = tracing_subscriber::registry().with(ConstraintLayer::default());
    tracing::subscriber::with_default(subscriber, || {
        let root = tracing::info_span!(target: "r1cs", "root_constraint");
        let _root = root.enter();
        let child = tracing::info_span!(target: "r1cs", "child_constraint");
        let _child = child.enter();
        let trace = ConstraintTrace::capture().expect("active constraint span");
        let names: Vec<_> = trace.path().into_iter().map(|step| step.name).collect();
        assert_eq!(names, ["root_constraint", "child_constraint"]);
        let formatted = trace.to_string();
        assert!(formatted.contains("root_constraint"));
        assert!(formatted.contains("child_constraint"));
    });
    assert!(ConstraintTrace::capture().is_none());
}
