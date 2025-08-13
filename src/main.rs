use aes_gcm::{ Aes256Gcm, Key, Nonce };
use aes_gcm::aead::{ Aead, KeyInit };
use clap::Parser;
use glob::glob;
use rand::{ rngs::OsRng, RngCore };
use rsa::pkcs8::LineEnding;
use rsa::{ RsaPrivateKey, Oaep };
use rsa::pkcs1::{ EncodeRsaPrivateKey, DecodeRsaPrivateKey };
use sha2::Sha256;
use std::fs::{ self, File };
use std::io::{ BufReader, BufWriter, Read, Write };
use std::path::Path;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB
const NONCE_SIZE: usize = 12; // 12 Bit

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long, value_parser = ["encrypt", "decrypt", "e", "d"])]
    mode: String,

    #[arg(short = 'i', long)]
    input: String,

    #[arg(short = 'o', long)]
    output: Option<String>,

    #[arg(short = 'k', long, help = "Path to keys.bin (optional for decrypt)")]
    key: Option<String>,
}

// Create zippy dir if exsit then increass count by 1
fn create_dir(base: &str) -> std::io::Result<String> {
    let mut index = 0;
    loop {
        let dir_name = if index == 0 { base.to_string() } else { format!("{}_{}", base, index) };
        let path = Path::new(&dir_name);
        if !path.exists() {
            fs::create_dir(&path)?;
            return Ok(dir_name);
        }
        index += 1;
    }
}

/*
    Accoding to the pattern it's encrypte the data and store it on zippy_enc with key
*/

fn encrypt_files(pattern: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // OsRng for crypto safe
    let mut rng = OsRng;

    // Gen Rsa key with size 2048
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = private_key.to_public_key();

    let mut aes_key = [0u8; 32];
    rng.fill_bytes(&mut aes_key);
    // Gen aes_key
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(aes_key);

    let encrypted_key = public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), aes_key.as_slice())?;

    // dyn case windows and linux
    let line_ending = if cfg!(windows) { LineEnding::CRLF } else { LineEnding::LF };
    // Parse private key into .prm format
    let private_pem = private_key.to_pkcs1_pem(line_ending)?;
    let private_pem_bytes = private_pem.as_bytes();
    let pem_len = private_pem_bytes.len() as u32;

    // Write keys.bin
    let key_path = Path::new(output_path).parent().unwrap().join("keys.bin");
    let mut key_file = BufWriter::new(File::create(key_path)?);
    key_file.write_all(&pem_len.to_be_bytes())?;
    key_file.write_all(private_pem_bytes)?;
    key_file.write_all(&encrypted_key)?; // Public key
    key_file.flush()?;

    // Write Encrypt data
    let mut writer = BufWriter::new(File::create(output_path)?);
    // Glob parse the pattern
    for entry in glob(pattern)? {
        let path = entry?;
        let file_name = path.file_name().unwrap().to_string_lossy();
        let name_bytes = file_name.as_bytes();

        if name_bytes.len() > (u16::MAX as usize) {
            return Err(format!("Filename too long: {file_name}").into());
        }
        // Write name on Enc_File
        writer.write_all(&(name_bytes.len() as u16).to_be_bytes())?; // File_name len as big endian
        writer.write_all(name_bytes)?;

        let mut file = BufReader::new(File::open(&path)?); // Open targeted file
        let file_len = file.get_ref().metadata()?.len(); // Get len
        writer.write_all(&(file_len as u64).to_be_bytes())?; // As Big endian

        let mut buffer = vec![0u8; CHUNK_SIZE]; // Buffer size
        let mut remaining = file_len;
        while remaining > 0 {
            let to_read = CHUNK_SIZE.min(remaining.try_into().unwrap()); // Check is chunk size <= remaining
            let n = file.read(&mut buffer[..to_read])?;

            // If no data left
            if n == 0 {
                break;
            }
            // Gen Number only once for every chunk
            let mut nonce = [0u8; NONCE_SIZE];
            rng.fill_bytes(&mut nonce);
            let nonce_ref = Nonce::from_slice(&nonce);
            // Parse chunk into cipher text
            let ciphertext = cipher
                .encrypt(nonce_ref, &buffer[..n])
                .map_err(|e| panic!("Aes encryption failed: {e}"))?;

            writer.write_all(&nonce)?; // 12 bit nonce
            writer.write_all(&(ciphertext.len() as u32).to_be_bytes())?; // Cipher text len as 32 bit big endian
            writer.write_all(&ciphertext)?;

            remaining -= n as u64; // Reduce by n
        }
    }
    writer.flush()?; // Flush the data
    Ok(())
}

fn decrypt_files(
    input_path: &str,
    key_path_opt: Option<&str>,
    output_dir: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let key_path = if let Some(custom_key) = key_path_opt {
        Path::new(custom_key).to_path_buf()
    } else {
        Path::new(input_path).parent().unwrap().join("keys.bin")
    };
    let mut keys = BufReader::new(File::open(key_path)?);

    let mut len_buf = [0u8; 4];
    keys.read_exact(&mut len_buf)?;
    let pem_len = u32::from_be_bytes(len_buf) as usize;

    let mut pem_buf = vec![0u8; pem_len];
    keys.read_exact(&mut pem_buf)?;
    let private_key_pem = String::from_utf8(pem_buf)?;
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem)?;

    let mut encrypted_key = Vec::new();
    keys.read_to_end(&mut encrypted_key)?;
    let aes_key = private_key.decrypt(Oaep::new::<Sha256>(), &encrypted_key)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(aes_key);

    fs::create_dir_all(output_dir)?;
    let mut reader = BufReader::new(File::open(input_path)?);

    while let Ok(_) = reader.read_exact(&mut len_buf[..2]) {
        let name_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
        let mut name_buf = vec![0u8; name_len];
        reader.read_exact(&mut name_buf)?;
        let filename = String::from_utf8(name_buf)?;

        let mut file_len_buf = [0u8; 8];
        reader.read_exact(&mut file_len_buf)?;
        let file_len = u64::from_be_bytes(file_len_buf);

        let mut output = BufWriter::new(File::create(Path::new(output_dir).join(&filename))?);

        let mut remaining = file_len;
        while remaining > 0 {
            let mut nonce = [0u8; NONCE_SIZE];
            reader.read_exact(&mut nonce)?;

            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let chunk_len = u32::from_be_bytes(len_buf) as usize;

            let mut ciphertext = vec![0u8; chunk_len];
            reader.read_exact(&mut ciphertext)?;

            let plaintext = cipher
                .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|e| panic!("Aes decryption failed: {e}"))?;
            output.write_all(&plaintext)?;

            remaining -= plaintext.len() as u64;
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.mode.as_str() {
        "encrypt" | "e" => {
            let enc_dir = create_dir("zippy_enc")?;
            let output = format!("{}/{}", enc_dir, cli.output.unwrap());
            encrypt_files(&cli.input, &output)?;
        }
        "decrypt" | "d" => {
            let dec_dir = create_dir("zippy_dnc")?;
            decrypt_files(&cli.input, cli.key.as_deref(), &dec_dir)?;
        }
        _ => {
            eprintln!("Invalid mode: use encrypt/e or decrypt/d");
        }
    }

    Ok(())
}
