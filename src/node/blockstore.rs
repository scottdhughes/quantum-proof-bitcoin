use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::Result;

pub fn ensure_dir(datadir: &Path) -> Result<()> {
    fs::create_dir_all(datadir.join("blocks"))?;
    Ok(())
}

pub fn put_block(datadir: &Path, hash_hex: &str, bytes: &[u8]) -> Result<()> {
    ensure_dir(datadir)?;
    let dir = datadir.join("blocks");
    let tmp = dir.join(format!("{hash_hex}.tmp"));
    let final_path = dir.join(format!("{hash_hex}.bin"));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(tmp, final_path)?;
    Ok(())
}

pub fn get_block(datadir: &Path, hash_hex: &str) -> Result<Option<Vec<u8>>> {
    let path = datadir.join("blocks").join(format!("{hash_hex}.bin"));
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read(path)?))
}
