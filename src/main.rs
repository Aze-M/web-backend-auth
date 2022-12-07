//TODO:
//finish login system to insert tokens
//start logout to delete all tokens for account
//start register with account checks.

#[macro_use]
extern crate rocket;

use std::fmt::format;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::vec;

use mysql::prelude::Queryable;
use mysql::{from_row, Row};
use mysql::{Conn, Opts, Pool};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::uri::Query;
use rocket::http::{Header, Status};
use rocket::serde::json::Json;
use rocket::serde::json::*;
use rocket::serde::{Deserialize, Serialize};
use rocket::{Request, Response};

use sha2::*;

//Manual CORS implementation
pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

//Defining workable objects
#[derive(Debug, Deserialize, Serialize)]
struct Account {
    id: i128,
    name: String,
    password: String,
    gravatar: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Token {
    id: i128,
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Options {
    port: i128,
    database: String,
    arbstring: String,
}

struct AccFetchSettings {
    id: Option<i128>,
    username: Option<String>,
    password: Option<String>,
}

//general Functions
fn generate_token(acc: Account, pool: &Pool) -> Option<Token> {
    //Make a random token
    let mut crypt = Sha512::new();
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    crypt.update(rand_string);

    let user_token = Token {
        id: acc.id,
        token: format!("{:x}", crypt.finalize()),
    };

    //insert generated token in to db, remove old tokens for account id.
    let conn = pool.get_conn();

    if conn.is_ok() {
        let del_query = format!("DELETE FROM sessions WHERE userid = '{}'", user_token.id);
        let ins_query = format!(
            "INSERT INTO sessions (userid, token) VALUES ('{}','{}') ",
            &user_token.id, user_token.token
        );
        let mut conn = conn.unwrap();
        let del = conn.query::<Row, &str>(&del_query);
        let ins = conn.query::<Row, &str>(&ins_query);
        
        if ins.is_err() || del.is_err() {
            return None;
        }

    } else {
        return None;
    }

    return Some(user_token);
}

fn validate_token(tok: &Token, pool: &Pool) -> bool {
    let query = format!("SELECT * FROM sessions WHERE token = '{}'", tok.token);
    let conn = pool.get_conn();

    if conn.is_ok() {
        let res = conn.unwrap().query::<Row, &str>(&query);

        println!("{:?}",res);

        if res.is_err() {
            return false;
        }

        let res = res.unwrap();

        if res.len() == 0 {
            return false;
        }

        return true;
    }

    return false;
}

fn find_account(search: AccFetchSettings, pool: &Pool) -> Option<Account> {
    //define used vars in outer scope
    let mut options: Vec<String> = Vec::new();
    let mut acc: Account;

    //add used search parameters
    if search.id.is_some() {
        options.push(format!("id = '{}'", search.id.unwrap()));
    }

    if search.username.is_some() {
        options.push(format!("username = '{}'", search.username.unwrap()));
    }

    if search.password.is_some() {
        options.push(format!("password = '{}'", search.password.unwrap()));
    }

    let query = format!("SELECT * FROM accounts WHERE {} ", options.join(" AND "));

    let mut conn = pool.get_conn().unwrap();

    for row in conn.query::<Row, &str>(&query).unwrap() {
        let data = from_row::<Row>(row.clone());

        acc = Account {
            id: data.get(0).unwrap(),
            name: data.get(1).unwrap(),
            password: data.get(2).unwrap(),
            gravatar: data.get(3).unwrap(),
        };

        return Some(acc);
    }

    return None;
}

fn load_config() -> Option<Options> {
    //Path to config
    let path: &Path = Path::new("./config/config.json");
    let display = path.display();
    let file = File::open(path);

    //None if the file fails to load, log to console.
    if !file.is_ok() {
        println!("Could not load file {:?}", display);
        println!("Work dir {:?}", std::env::current_dir());
        return None;
    }

    //parse file into usable struct
    let mut config = file.unwrap();
    let mut config_buffer = String::new();
    config.read_to_string(&mut config_buffer).unwrap();

    let conf_js: Options = serde_json::from_str(&config_buffer).unwrap();

    Some(conf_js)
}

//Handling logins
#[post("/auth/login", format = "json", data = "<json>")]
fn login(json: Json<Value>) -> Result<Json<Token>, Status> {
    //load config
    let config = load_config();

    //error if the config fails to load
    if config.is_none() {
        return Err(Status::InternalServerError);
    }

    let conf_unw = config.unwrap();

    //get used vars out of config
    let arb = String::from(conf_unw.arbstring);
    let db = Opts::from_url(&conf_unw.database);

    //create connection pool to pass onto lower functions
    let pool;

    if db.is_ok() {
        pool = Pool::new(db.unwrap()).unwrap();
    } else {
        return Err(Status::InternalServerError);
    }

    //define request and reserve for token
    let incoming_request = json.as_object().unwrap();
    let user_token: Option<Token>;

    //decline bad requests
    if !incoming_request.contains_key("name") || !incoming_request.contains_key("password") {
        return Err(Status::BadRequest);
    }

    //on good requests, move name and password to variables for ease of use, add arbitration to password
    let name = incoming_request.get("name").unwrap().as_str().unwrap();
    let mut pwd: String = format!(
        "{}{}",
        incoming_request.get("password").unwrap().as_str().unwrap(),
        arb
    );

    //encrypt password
    let mut crypt = Sha512::new();
    crypt.update(pwd);
    pwd = format!("{:x}", crypt.finalize());

    //find the accound
    let acc = find_account(
        AccFetchSettings {
            id: None,
            username: Some(name.into()),
            password: Some(pwd.into()),
        },
        &pool,
    );

    //if it does not exist return badrequest
    if !acc.is_some() {
        return Err(Status::BadRequest);
    }

    //Generate a new token for acc
    user_token = generate_token(acc.unwrap(), &pool);

    if user_token.is_none() {
        return Err(Status::InternalServerError);
    }

    let user_token = user_token.unwrap();

    if validate_token(&user_token, &pool) {
        return Ok(Json::from(user_token));
    }

    return Err(Status::BadRequest);
}

//Handling logouts
#[post("/auth/logout", format = "json", data = "<json>")]
fn logout(json: Json<Value>) -> Json<Token> {
    let incoming_request = json.as_object().unwrap();
    let user_token = Token {
        id: 1,
        token: "aassdd".into(),
    };

    Json::from(user_token)
}

//Handling registration
#[post("/auth/register", format = "json", data = "<json>")]
fn register(json: Json<Value>) -> Json<Token> {
    let incoming_request = json.as_object().unwrap();
    let user_token = Token {
        id: 1,
        token: "aassdd".into(),
    };

    Json::from(user_token)
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![login, logout, register])
        .attach(CORS)
}
