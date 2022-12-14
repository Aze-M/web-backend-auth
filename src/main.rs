//TODO:

//start logout to delete all tokens for account
//start register with account checks.

#[macro_use]
extern crate rocket;

use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::Path;
use std::vec;

use mysql::prelude::{Queryable};
use mysql::{from_row, params, Row};
use mysql::{Opts, Pool};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Header, Status};
use rocket::serde::json::Json;
use rocket::serde::json::*;
use rocket::serde::{Deserialize, Serialize};
use rocket::{Config, Request, Response};

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
    id: Option<i128>,
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Options {
    port: u16,
    database: String,
    arbstring: String,
}

struct AccFetchSettings {
    id: Option<i128>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

// impl<'a, 'r> FromRequest<'a, 'r> for Token {
//     type Error = Infallible;

//     fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
//         let token = request.headers().get_one("Authorization");
//     }
// }

//Config
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

//general Functions
fn purge_tokens(acc: Account, pool: &Pool) -> bool {
    let conn = pool.get_conn();

    if conn.is_err() {
        return false;
    }
    let mut conn = conn.unwrap();

    let stmt = conn
        .prep("DELETE FROM sessions WHERE userid = :id")
        .unwrap();

    let del: Result<Vec<Row>, mysql::Error> = conn.exec(&stmt, params! { "id" => acc.id });

    if del.is_err() {
        return false;
    }

    return true;
}

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
        id: Some(acc.id),
        token: format!("{:x}", crypt.finalize()),
    };

    //insert generated token in to db, remove old tokens for account id.
    let conn = pool.get_conn();

    if !purge_tokens(acc, pool) {
        return None;
    };

    if conn.is_err() {
        return None;
    }
    //build query to insert token into db
    let mut conn = conn.unwrap();

    let stmt = conn
        .prep("INSERT INTO sessions ( userid , token ) VALUES ( :userid , :token )")
        .unwrap();

    let ins: Result<Vec<Row>, mysql::Error>  = conn.exec(
        &stmt,
        params! {"userid" => &user_token.id.unwrap(), "token" => &user_token.token},
    );

    //if it errors return none to trigger error catch
    if ins.is_err() {
        return None;
    }

    return Some(user_token);
}

fn validate_token(tok: &Token, pool: &Pool) -> bool {
    //unsafe query is fine since this if only called by token generation.
    let query = format!("SELECT * FROM sessions WHERE token = '{}'", tok.token);
    let conn = pool.get_conn();

    if conn.is_err() {
        return false;
    }
    let mut conn = conn.unwrap();

    let res: Result<Vec<Row>, mysql::Error>  = conn.query::<Row, &str>(&query);

    if res.is_err() {
        return false;
    }

    let res = res.unwrap();

    if res.len() == 0 {
        return false;
    }

    return true;
}

fn find_account(search: AccFetchSettings, pool: &Pool) -> Option<Account> {
    //define used vars in outer scope
    let mut options: Vec<String> = Vec::new();
    let acc: Account;

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

    //unsafe , needs reworking
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

fn find_account_id_from_token(search: AccFetchSettings, pool: &Pool) -> Option<i128> {
    if search.token.is_none() {
        return None;
    }

    let mut conn = pool.get_conn().unwrap();

    let stmt = conn
        .prep("SELECT userid FROM sessions where token = :token")
        .unwrap();

    let exec: Result<Vec<Row>, mysql::Error> = conn
    .exec(&stmt, params! {"token" => search.token.unwrap().as_str()});


    for row in exec.unwrap()
    {
        let data = from_row::<Row>(row.clone());

        println!("{:?}", data);

        return Some(data.get(0).unwrap());
    }

    return None;
}

fn insert_account(name: String, pwd: String, gravatar: String, pool: &Pool) -> Option<Account> {
    let mut conn = pool.get_conn().unwrap();

    let query = conn.prep("INSERT INTO accounts (username,password,gravatar) VALUES (:username,:password,:gravatar)").unwrap();

    let exec: Result<Vec<Row>, mysql::Error>  = conn.exec(&query,params! {"username" => &name, "password" => &pwd, "gravatar" => &gravatar});

    for row in exec.unwrap() {
        let data = from_row::<Row>(row.clone());

        println!("{:?}", data);
    }

    let search = AccFetchSettings {
        id: None,
        username: Some(name),
        password: Some(pwd),
        token: None,
    };

    let acc = find_account(search, pool);

    if acc.is_some() {
        return acc;
    }

    return None;
}

//Handling logins
#[post("/auth/login", format = "json", data = "<json>")]
fn login(json: Json<Value>) -> Result<Json<Token>, Status> {
    println!("Recieved login request");

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
            token: None,
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
fn logout(json: Json<Value>) -> Status {
    println!("Recieved logout request");

    //load config
    let config = load_config();

    //error if the config fails to load
    if config.is_none() {
        return Status::InternalServerError;
    }

    let conf_unw = config.unwrap();

    //get used vars out of config
    let db = Opts::from_url(&conf_unw.database);

    //create connection pool to pass onto lower functions
    let pool;

    if db.is_ok() {
        pool = Pool::new(db.unwrap()).unwrap();
    } else {
        return Status::InternalServerError;
    }

    let incoming_request = json.as_object().unwrap();

    let mut search = AccFetchSettings {
        id: None,
        username: None,
        password: None,
        token: Some(
            incoming_request
                .get("token")
                .unwrap()
                .as_str()
                .unwrap()
                .into(),
        ),
    };

    println!("{:?}", search.token);

    let affected_account_id = find_account_id_from_token(search, &pool);

    if affected_account_id.is_none() {
        return Status::Unauthorized;
    }

    search = AccFetchSettings {
        id: affected_account_id,
        username: None,
        password: None,
        token: None,
    };
    let affected_account = find_account(search, &pool);

    if affected_account.is_none() {
        return Status::InternalServerError;
    }

    purge_tokens(affected_account.unwrap(), &pool);

    return Status::Ok;
}

//Handling registration
#[post("/auth/register", format = "json", data = "<json>")]
fn register(json: Json<Value>) -> Result<Json<Token>, Status> {
    println!("Recieved register request");

    //load config
    let config = load_config();

    //error if the config fails to load
    if config.is_none() {
        return Err(Status::InternalServerError);
    }

    let conf_unw = config.unwrap();

    //get used vars out of config
    let db = Opts::from_url(&conf_unw.database);
    let arb = conf_unw.arbstring;

    //create connection pool to pass onto lower functions
    let pool;

    if db.is_ok() {
        pool = Pool::new(db.unwrap()).unwrap();
    } else {
        return Err(Status::InternalServerError);
    }

    let incoming_request = json.as_object().unwrap();

    if incoming_request.get("username").is_none() || incoming_request.get("password").is_none() {
        return Err(Status::BadRequest);
    }

    //redefine for ease of use
    let name = incoming_request.get("username").unwrap().as_str().unwrap();
    let mut pwd: String = format!(
        "{}{}",
        incoming_request.get("password").unwrap().as_str().unwrap(),
        arb
    );
    let gravatar = incoming_request.get("gravatar").unwrap().as_str().unwrap();

    //crypt password
    let mut crypt = Sha512::new();
    crypt.update(pwd);
    pwd = format!("{:x}", crypt.finalize());

    let search = AccFetchSettings {
        id: None,
        username: Some(name.into()),
        password: None,
        token: None,
    };

    let account_check = find_account(search, &pool);

    if account_check.is_some() {
        return Err(Status::BadRequest);
    }

    let acc = insert_account(name.into(), pwd, gravatar.into(), &pool);

    if acc.is_none() {
        return Err(Status::InternalServerError);
    }

    let acc = acc.unwrap();

    let initial_token = generate_token(acc, &pool);

    if initial_token.is_none() {
        return Err(Status::InternalServerError);
    }

    return Ok(Json::from(initial_token.unwrap()));
}

#[post("/auth/getinfo", format = "json", data = "<json>")]
fn getinfo(json: Json<Value>) -> Result<Json<Account>, Status> {
    println!("Recieved register request");

    //load config
    let config = load_config();

    //error if the config fails to load
    if config.is_none() {
        return Err(Status::InternalServerError);
    }

    let conf_unw = config.unwrap();

    //get used vars out of config
    let db = Opts::from_url(&conf_unw.database);

    //define connection pool if db string can be parsed
    let pool;

    if db.is_ok() {
        pool = Pool::new(db.unwrap()).unwrap();
    } else {
        return Err(Status::InternalServerError);
    }

    let incoming_request = json.as_object().unwrap();

    let mut search = AccFetchSettings {
        id: None,
        username: None,
        password: None,
        token: Some(
            incoming_request
                .get("token")
                .unwrap()
                .as_str()
                .unwrap()
                .into(),
        ),
    };

    let id = find_account_id_from_token(search, &pool);

    if id.is_none() {
        return Err(Status::BadRequest);
    }

    search = AccFetchSettings {
        id: id,
        username: None,
        password: None,
        token: None,
    };

    let acc = find_account(search, &pool);

    if acc.is_none() {
        return Err(Status::InternalServerError);
    }

    return Ok(Json::from(acc.unwrap()));
}

#[launch]
fn rocket() -> _ {
    let conf_file = load_config();

    if conf_file.is_none() {
        panic!("Could not load config!");
    }

    let conf_file = conf_file.unwrap();

    let conf = Config {
        port: conf_file.port,
        address: std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        ..Config::default()
    };

    println!("Started @ {} : {}", conf.address, conf.port);

    rocket::custom(&conf)
        .mount("/", routes![login, logout, register, getinfo])
        .attach(CORS)
}
