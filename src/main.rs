#[macro_use]
extern crate rocket;

use rocket::http::{ContentType, Header, Status};
use rocket::{Request, Response};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::serde::json::Json;
use rocket::serde::json::*;
use rocket::serde::{Deserialize, Serialize};
use sha2::*;

//Constants
const ARB_STRING: &str = "hYdN";

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
    password: &'static str,
}

#[derive(Debug, Deserialize, Serialize)]
struct Token {
    id: i128,
    token: String,
}

struct AccFetchSettings {
    id: Option<i128>,
    name: Option<String>,
    password: Option<String>,
}

//general Functions
fn generate_token(acc: Account) -> Token {
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

    return user_token;
}

fn validate_token(tok: Token) -> bool {
    true
}

fn find_account(search: AccFetchSettings) -> Option<Account> {
    return Some(Account {
        id: 420,
        name: "Aze".into(),
        password: "wow".into(),
    });
}

//Handling logins
#[post("/auth/login", format = "json", data = "<json>")]
fn login(json: Json<Value>) -> Result<Json<Token>, Status> {
    //define request and reserve for token
    let incoming_request = json.as_object().unwrap();
    let user_token: Token;

    //decline bad requests
    if !incoming_request.contains_key("name") || !incoming_request.contains_key("password") {
        return Err(Status::BadRequest);
    }

    //on good requests, move name and password to variables for ease
    let name = incoming_request.get("name").unwrap().to_string();
    let mut pwd = incoming_request.get("password").unwrap().to_string() + ARB_STRING;

    //encrypt password
    let mut crypt = Sha512::new();
    crypt.update(pwd);
    pwd = format!("{:x}", crypt.finalize());

    //find the accound
    let acc = find_account(AccFetchSettings {
        id: None,
        name: Some(name),
        password: Some(pwd.into()),
    });

    //if it does not exist return badrequest
    if !acc.is_some() {
        return Err(Status::BadRequest);
    }

    //Generate a new token for
    user_token = generate_token(acc.unwrap());

    Ok(Json::from(user_token))
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
