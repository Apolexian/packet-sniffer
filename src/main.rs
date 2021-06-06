extern crate argparse;
extern crate dotenv;
extern crate pcap;
extern crate s3;

use argparse::{ArgumentParser, Store, StoreTrue};
use pcap::{Capture, Device};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::S3Error;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio;

fn show_devices(devices: &Vec<Device>) {
    for device in devices {
        println!("\tDevice {:?} : {:?}", device.name, device.desc);
    }
}

fn save_device(device_name: &str, requested_device: &mut Device, devices_vector: &Vec<Device>) {
    for device in devices_vector {
        if &*device.name == device_name {
            requested_device.name = device.name.clone();
            requested_device.desc = device.desc.clone();
        };
    }
}

#[tokio::main]
async fn upload_to_s3(file_name: &str) -> Result<(), S3Error> {
    dotenv::dotenv().expect("Failed to read .env file");
    let access_key: String = env::var("ACCESS_KEY").expect("Could not read access key");
    let secret_key: String = env::var("SECRET_KEY").expect("Could not read secret key");
    let bucket_name = env::var("BUCKET_NAME").expect("BUCKET_NAME not found");
    let region: s3::Region = s3::Region::EuWest1;
    let credentials: Credentials =
        Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
            .expect("Could not init credentials");
    let bucket: Bucket =
        Bucket::new(&bucket_name, region, credentials).expect("Could not init s3 bucket");
    let file: Vec<u8> = std::fs::read(&file_name).expect("Can not read file");
    bucket.put_object(format!("/{}", &file_name), &file).await?;
    println!("Uploaded to bucket: {}", bucket.name);
    Ok(())
}

fn main() {
    let mut requested_device: Device = Device::lookup().unwrap();
    let mut print_flag: bool = false;
    let mut device_name: String = "wlp2s0".to_string();

    {
        let mut arg_parser = ArgumentParser::new();
        arg_parser.refer(&mut print_flag).add_option(
            &["--p", "--print"],
            StoreTrue,
            "Show available devices",
        );
        arg_parser.refer(&mut device_name).add_option(
            &["--d", "--device"],
            Store,
            "Name of the device",
        );
        arg_parser.set_description("Packet sniffer");
        arg_parser.parse_args_or_exit();
    }

    let devices = Device::list();
    match devices {
        Ok(device_vector) => {
            if print_flag {
                show_devices(&device_vector);
                std::process::exit(0);
            }
            save_device(&device_name, &mut requested_device, &device_vector);
        }
        Err(_) => {
            println!("No devices found");
            std::process::exit(1);
        }
    }
    let mut captured_device = Capture::from_device(requested_device)
        .unwrap()
        .open()
        .unwrap();
    let start_time = SystemTime::now();
    let time_since_the_epoch = start_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let mut start_time_in_seconds = time_since_the_epoch.as_secs();
    let mut i = 1;
    let mut file_name = format!("dump{}.pcap", i);
    let mut file: pcap::Savefile = match captured_device.savefile(file_name) {
        Ok(f) => f,
        Err(_) => std::process::exit(1),
    };
    while let Ok(packet) = captured_device.next() {
        file.write(&packet);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        if current_time - start_time_in_seconds > 43200 {
            file_name = format!("dump{}.pcap", i);
            upload_to_s3(&file_name).expect("Failed to upload");
            i += 1;
            file_name = format!("dump{}.pcap", i);
            println!("Writing to new file: {}", &file_name);
            file = match captured_device.savefile(&file_name) {
                Ok(f) => f,
                Err(_) => std::process::exit(1),
            };
            start_time_in_seconds = current_time;
        }
    }
}
