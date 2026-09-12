#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::perf)]
use crate::{sec_landlock::appl_landlock, sec_seccomp::appl_seccomp};
use bendy::decoding::{Decoder, Error, Object};
use hex::encode as hex_encode;
use sha1::{Digest, Sha1};
use std::{collections::BTreeMap, env, fs, process};
use urlencoding::encode;

mod sec_landlock;
mod sec_seccomp;

// ---------- своё дерево bencode-значений ----------
#[derive(Debug)]
enum BValue {
    Bytes(Vec<u8>),
    Integer(i64),
    List(Vec<Self>),
    Dict(BTreeMap<Vec<u8>, Self>),
}
fn encode_bvalue(val: &BValue, out: &mut Vec<u8>) {
    match val {
        BValue::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        BValue::Integer(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        BValue::List(list) => {
            out.push(b'l');
            for item in list {
                encode_bvalue(item, out);
            }
            out.push(b'e');
        }
        BValue::Dict(map) => {
            out.push(b'd');
            for (k, v) in map {
                out.extend_from_slice(k.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                encode_bvalue(v, out);
            }
            out.push(b'e');
        }
    }
}

// Рекурсивно превращаем потоковый Object в BValue
fn object_to_bvalue(obj: Object) -> Result<BValue, Error> {
    match obj {
        Object::Bytes(b) => Ok(BValue::Bytes(b.to_vec())),
        Object::Integer(s) => {
            let n: i64 = s.parse().map_err(Error::malformed_content)?;
            Ok(BValue::Integer(n))
        }
        Object::List(mut list) => {
            let mut vec = Vec::new();
            while let Some(item) = list.next_object()? {
                vec.push(object_to_bvalue(item)?);
            }
            Ok(BValue::List(vec))
        }
        Object::Dict(mut dict) => {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = dict.next_pair()? {
                map.insert(key.to_vec(), object_to_bvalue(value)?);
            }
            Ok(BValue::Dict(map))
        }
    }
}

// ---------- вспомогательные извлекатели ----------
fn get_dict<'a>(val: &'a BValue, key: &[u8]) -> Option<&'a BValue> {
    match val {
        BValue::Dict(map) => map.get(key),
        _ => None,
    }
}

fn get_bytes(val: &BValue) -> Option<&[u8]> {
    match val {
        BValue::Bytes(b) => Some(b),
        _ => None,
    }
}

const fn get_integer(val: &BValue) -> Option<i64> {
    match val {
        BValue::Integer(i) => Some(*i),
        _ => None,
    }
}

const fn get_list(val: &BValue) -> Option<&Vec<BValue>> {
    match val {
        BValue::List(list) => Some(list),
        _ => None,
    }
}

// ---------- main ----------
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Использование: {} <путь-к-торрент-файлу>", args[0]);
        process::exit(1);
    }

    appl_landlock(&args[1]).expect("LANDLOCK");
    appl_seccomp();
    let data = fs::read(&args[1]).unwrap_or_else(|e| {
        eprintln!("Ошибка чтения файла: {e}");
        process::exit(1);
    });

    let mut decoder = Decoder::new(&data);

    // Корневой объект обязательно должен быть словарём
    let root_obj = decoder.next_object().unwrap_or_else(|e| {
        eprintln!("Ошибка парсинга: {e}");
        process::exit(1);
    });

    let root_obj = root_obj.unwrap_or_else(|| {
        eprintln!("Файл пуст");
        process::exit(1);
    });

    let root = object_to_bvalue(root_obj).unwrap_or_else(|e| {
        eprintln!("Ошибка чтения структуры: {e}");
        process::exit(1);
    });

    let root = match &root {
        BValue::Dict(map) => map,
        _ => {
            eprintln!("Некорректный торрент-файл: ожидался словарь");
            process::exit(1);
        }
    };

    // --- общая информация ---
    let announce = root
        .get(b"announce".as_slice())
        .and_then(get_bytes)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("?");

    let comment = root
        .get(b"comment".as_slice())
        .and_then(get_bytes)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("");

    let creation_date = root
        .get(b"creation date".as_slice())
        .and_then(get_integer)
        .unwrap_or(0);

    // --- info-словарь ---
    let info_val = root.get(b"info".as_slice()).expect("Отсутствует info");
    let info = match info_val {
        BValue::Dict(map) => map,
        _ => {
            eprintln!("info должен быть словарём");
            process::exit(1);
        }
    };
    // --- info hash ---
    let mut info_bytes = Vec::new();
    encode_bvalue(info_val, &mut info_bytes);
    let mut hasher = Sha1::new();
    hasher.update(&info_bytes);
    let info_hash = hex_encode(&hasher.finalize());

    let name = info
        .get(b"name".as_slice())
        .and_then(get_bytes)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("неизвестно");

    let piece_length = info
        .get(b"piece length".as_slice())
        .and_then(get_integer)
        .map(|i| i as u64)
        .unwrap_or(0);

    // --- файлы ---
    let files: Vec<(Vec<String>, u64)> = if let Some(len_val) = info.get(b"length".as_slice()) {
        let len = get_integer(len_val).map(|i| i as u64).unwrap_or(0);
        vec![(vec![name.to_string()], len)]
    } else if let Some(files_val) = info.get(b"files".as_slice()) {
        let list = get_list(files_val).expect("files должен быть списком");
        let mut result = Vec::new();
        for file in list {
            if let BValue::Dict(file_dict) = file {
                let length = file_dict
                    .get(b"length".as_slice())
                    .and_then(get_integer)
                    .map(|i| i as u64)
                    .unwrap_or(0);
                let path: Vec<String> = file_dict
                    .get(b"path".as_slice())
                    .and_then(get_list)
                    .map(|components| {
                        components
                            .iter()
                            .filter_map(get_bytes)
                            .filter_map(|b| std::str::from_utf8(b).ok())
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default();
                result.push((path, length));
            }
        }
        result
    } else {
        eprintln!("Ни 'length', ни 'files' не найдены в info");
        process::exit(1);
    };

    let total_size: u64 = files.iter().map(|(_, s)| s).sum();
    let magnet = format!(
        "magnet:?xt=urn:btih:{}&dn={}&tr={}",
        info_hash,
        encode(name),
        encode(announce)
    );
    // ---------- красивый вывод ----------
    println!("Информация о торренте");
    println!("{:-<60}", "");
    println!("Трекер (announce):  {announce}");
    println!("Info Hash (SHA1):    {info_hash}");
    println!("Magnet-ссылка:       {magnet}");
    if !comment.is_empty() {
        println!("Комментарий:         {comment}");
    }
    if creation_date > 0 {
        println!("Дата создания:       {creation_date} (Unix timestamp)");
    }
    println!("Имя раздачи:         {name}");
    println!("Размер куска:        {piece_length} байт");
    println!("Количество файлов:   {}", files.len());
    println!(
        "Общий размер:        {} байт ({:.2} МБ)",
        total_size,
        total_size as f64 / 1_048_576.0
    );
    println!("{:-<60}", "");

    if files.len() == 1 && files[0].0.len() == 1 && files[0].0[0] == name {
        println!("Файл: {name}");
    } else {
        println!("{:<50} {:>10}", "Путь", "Размер (байт)");
        println!("{:-<50} {:-<10}", "", "");
        for (path, size) in &files {
            let path_str = path.join("/");
            println!("{path_str:<50} {size:>10}");
        }
    }
}
