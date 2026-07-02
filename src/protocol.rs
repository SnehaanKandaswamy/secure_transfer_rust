use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]

pub struct DataPacket{

    pub chunk_id:u32,

    pub encrypted_size:u32,

    pub hash:u64,

    pub encrypted:Vec<u8>,

}

#[derive(Serialize,Deserialize,Debug)]

pub struct FinishPacket{

    pub total_chunks:u32,

    pub file_hash:u64,

}

#[derive(Serialize,Deserialize,Debug)]

pub struct MissingPacket{

    pub missing_chunks:Vec<u32>,

}