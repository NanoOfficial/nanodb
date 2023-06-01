// @file: cost.rs
// @author: Krisna Pranav
use proto::session_proto::QuerySessionInfo;

const C_CREATEDB_GAS_PRICE: u64 = 100; 
const C_CREATECOLLECTION_GAS_PRICE: u64 = 100; 
const C_CREATEINDEX_GAS_PRICE: u64 = 100; 
const C_ADD_DOC_GAS_PRICE: u64 = 200; 
const C_DEL_DOC_GAS_PRICE: u64 = 200; 
const C_UPDATE_DOC_GAS_PRICE: u64 = 200; 
const STORAGE_GAS_PRICE: u64 = 1; 
                                  
const C_QUERY_OP_GAS_PRICE: u64 = 100;
#[derive(PartialEq, Eq, Debug)]
pub enum DbStoreOp {
    DbOp {
        create_db_ops: u64,
        create_collection_ops: u64,
        create_index_ops: u64,
        data_in_bytes: u64,
    },

    DocOp {
        add_doc_ops: u64,
        del_doc_ops: u64,
        update_doc_ops: u64,
        data_in_bytes: u64,
    },
}

impl DbStoreOp {
    pub fn update_data_size(&mut self, data_size: u64) {
        match self {
            DbStoreOp::DbOp {
                ref mut data_in_bytes,
                ..
            } => {
                *data_in_bytes = data_size;
            }
            DbStoreOp::DocOp {
                ref mut data_in_bytes,
                ..
            } => {
                *data_in_bytes = data_size;
            }
        }
    }
    pub fn get_data_size(&self) -> u64 {
        match self {
            DbStoreOp::DbOp { data_in_bytes, .. } => *data_in_bytes,
            DbStoreOp::DocOp { data_in_bytes, .. } => *data_in_bytes,
        }
    }
}

pub fn estimate_gas(ops: &DbStoreOp) -> u64 {
    match ops {
        DbStoreOp::DbOp {
            create_db_ops,
            create_collection_ops,
            create_index_ops,
            data_in_bytes,
        } => {
            C_CREATEDB_GAS_PRICE * create_db_ops
                + C_CREATECOLLECTION_GAS_PRICE * create_collection_ops
                + C_CREATEINDEX_GAS_PRICE * create_index_ops
                + STORAGE_GAS_PRICE * data_in_bytes
        }
        DbStoreOp::DocOp {
            add_doc_ops,
            del_doc_ops,
            update_doc_ops,
            data_in_bytes,
        } => {
            C_DEL_DOC_GAS_PRICE * add_doc_ops
                + C_ADD_DOC_GAS_PRICE * del_doc_ops
                + C_UPDATE_DOC_GAS_PRICE * update_doc_ops
                + STORAGE_GAS_PRICE * data_in_bytes
        }
    }
}

pub fn estimate_query_session_gas(query_session_info: &QuerySessionInfo) -> u64 {
    C_QUERY_OP_GAS_PRICE * query_session_info.query_count as u64
}
