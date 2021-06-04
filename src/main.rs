extern crate argparse;
extern crate pcap;

use argparse::{ArgumentParser, Store, StoreTrue};
use pcap::{Capture, Device};

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

    let mut file: pcap::Savefile = match captured_device.savefile("./dump.pcap") {
        Ok(f) => f,
        Err(_) => std::process::exit(1),
    };

    while let Ok(packet) = captured_device.next() {
        println!("Got a packet: {:?}", packet.header);
        file.write(&packet);
    }
}