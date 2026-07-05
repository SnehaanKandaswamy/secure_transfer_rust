//BEST
mod protocol;
mod crypto;
mod checksum;
mod network;
mod config;
mod fileio;
mod sender;
mod receiver;
mod pipeline;
use anyhow::Result;
use std::env;
mod transport;
use sender::Sender;
mod buffer_pool;
fn main() -> Result<()> {

    let args:Vec<String>=env::args().collect();

    if args.len()<2{

        println!("Usage:");

        println!("cargo run -- receiver");

        println!("cargo run -- sender <file>");

        return Ok(());

    }

    match args[1].as_str(){

        "receiver"=>{

            receiver::run()?;

        }

        "sender"=>{

            if args.len()<3{

                println!("Missing filename");

                return Ok(());

            }

            let mut sender=Sender::new(&args[2])?;

            sender.run()?;

        }

        _=>{

            println!("Unknown command");

        }

    }

    Ok(())

}