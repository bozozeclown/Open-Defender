use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use exploit_detector::analytics::detection::AdvancedDetectionEngine;
use exploit_detector::cache::DetectionCache;
use exploit_detector::collectors::DataEvent;
use exploit_detector::config::AppConfig;
use exploit_detector::database::DatabaseManager;
use std::sync::Arc;
use tokio::runtime::Runtime;
use std::time::Duration;

fn benchmark_detection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = rt.block_on(async {
        AppConfig::from_env().expect("Failed to load config")
    });
    
    let (detection_engine, _) = rt.block_on(async {
        let db_manager = DatabaseManager::new(&config).await.unwrap();
        let cache = Arc::new(DetectionCache::new(1000));
        
        let engine = AdvancedDetectionEngine::new(
            Arc::new(config),
            db_manager.get_pool().clone(),
            cache.clone(),
        );
        engine.initialize().await.unwrap();
        
        (engine, cache)
    });
    
    let mut group = c.benchmark_group("detection");
    
    // Benchmark single event detection
    group.bench_function("single_event", |b| {
        b.to_async(&rt).iter(|| {
            let event = create_test_event();
            detection_engine.analyze(black_box(event))
        });
    });
    
    // Benchmark batch detection with different sizes
    for batch_size in [10, 50, 100, 500] {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(BenchmarkId::new("batch_detection", batch_size), &batch_size, |b, &size| {
            b.to_async(&rt).iter(|| {
                let events: Vec<DataEvent> = (0..size).map(|_| create_test_event()).collect();
                async {
                    for event in events {
                        let _ = detection_engine.analyze(event).await;
                    }
                }
            });
        });
    }
    
    // Cold start benchmark
    group.bench_function("cold_start", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let config = AppConfig::from_env().expect("Failed to load config");
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let db_manager = DatabaseManager::new(&config).await.unwrap();
                    let cache = Arc::new(DetectionCache::new(1000));
                    let engine = AdvancedDetectionEngine::new(
                        Arc::new(config),
                        db_manager.get_pool().clone(),
                        cache.clone(),
                    );
                    engine.initialize().await.unwrap();
                    (engine, rt)
                })
            },
            |(engine, _rt)| async move {
                let event = create_test_event();
                engine.analyze(black_box(event)).await
            },
            criterion::BatchSize::SmallInput,
        );
    });
    
    // Memory usage benchmark
    group.bench_function("memory_usage", |b| {
        b.to_async(&rt).iter(|| {
            let events: Vec<_> = (0..1000).map(|_| create_test_event()).collect();
            async {
                for event in events {
                    let _ = detection_engine.analyze(black_box(event)).await;
                }
            }
        });
    });
    
    group.finish();
}

fn create_test_event() -> DataEvent {
    DataEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: "network".to_string(),
        source: "benchmark".to_string(),
        data: exploit_detector::collectors::EventData::Network {
            src_ip: "192.168.1.1".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP".to_string(),
            bytes_sent: 1024,
            bytes_received: 2048,
        },
    }
}

criterion_group!(benches, benchmark_detection);
criterion_main!(benches);