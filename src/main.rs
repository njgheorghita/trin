use trin_core::{cli::TrinConfig, utils::provider::TrustedProvider};

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use trin::run_trin;

//
// - how does this interact w/ RUST_LOG?
//

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::Registry::default()
        .with(CustomLayer.with_filter(LevelFilter::INFO))
        .init();

    println!("Launching trin");

    let trin_config = TrinConfig::from_cli();
    let trusted_provider = TrustedProvider::from_trin_config(&trin_config);
    let exiter = run_trin(trin_config, trusted_provider).await?;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    exiter.exit();

    Ok(())
}

use std::collections::BTreeMap;
use tracing_subscriber::Layer;

pub struct CustomLayer;

impl<S> Layer<S> for CustomLayer
where
    S: tracing::Subscriber,
    S: for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Get the special place where tracing stores custom data
        println!("Got on_event!");

        // Covert the values into a JSON object
        let mut fields = BTreeMap::new();
        let mut visitor = JsonVisitor(&mut fields);
        event.record(&mut visitor);

        let span = ctx.event_span(event);
        if span.is_some() {
            let ext = span.unwrap();

            println!("parent span");
            println!("  name={}", ext.name());
            println!("  target={}", ext.metadata().target());

            println!();
            let mut extensions = ext.extensions_mut();
            // And get the custom data we stored out of it
            let storage: &CustomFieldStorage = extensions.get_mut().unwrap();
            let mut field_data: BTreeMap<String, u64> = storage.0.clone();
            let count = field_data.get("process_one_request").unwrap();
            let count = count + 1;
            field_data.insert("process_one_request".to_string(), count);
            extensions.replace::<CustomFieldStorage>(CustomFieldStorage(field_data));
        }
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let span = ctx.span(id).unwrap();
        println!("Got new_span!: {attrs:?}");

        // Build our json object from the field values like we have been
        let mut fields = BTreeMap::new();
        let mut visitor = JsonVisitor(&mut fields);
        attrs.record(&mut visitor);

        // And stuff it in our newtype.
        let storage = CustomFieldStorage(fields);

        // Get a reference to the internal span data
        let span = ctx.span(id).unwrap();
        // Get the special place where tracing stores custom data
        let mut extensions = span.extensions_mut();
        // And store our data
        extensions.insert::<CustomFieldStorage>(storage);
    }
}

struct JsonVisitor<'a>(&'a mut std::collections::BTreeMap<String, u64>);

impl<'a> tracing::field::Visit for JsonVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        println!("debug  field={} value={:?}", field.name(), value);
        println!("{:?}", self.0.get("process_one_request"));
        self.0.insert(format!("{value:?}"), 1);
    }
}

#[derive(Debug)]
struct CustomFieldStorage(std::collections::BTreeMap<String, u64>);
