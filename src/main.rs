

#[macro_use]
extern crate rocket;

use rocket::{Request, Response};
use rocket::http::Header;

use rocket::serde::json::*;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::fairing::{Fairing, Info, Kind};

use sha2::{Sha512, Digest, digest};
use mysql::{Pool, PooledConn, QueryResult, QueryWithParams, };

//Manual CORS implementation
pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET, PATCH, OPTIONS"));
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
    token: String
}

//Handling logins
#[post("/auth/login", format = "json", data = "<json>")]
fn login(json: Json<Value>) -> Json<Token> {
    let incoming_request = json.as_object().unwrap();
    let user_token = Token { id: 1, token: "aassdd".into()};

    if incoming_request.contains_key("id") {
        println!("{:?}", incoming_request.get("id").unwrap().to_string().parse::<i128>().unwrap());

        let mut crypt = Sha512::new();
        crypt.update(incoming_request.get("password").unwrap().to_string());
        let encr_pwd = format!("{:x}", crypt.finalize());

        println!("{:?}", encr_pwd);

    }

    Json::from(user_token)
}

//Handling logouts
#[post("/auth/logout", format = "json", data = "<json>")]
fn logout(json: Json<Value>) -> Json<Token> {
    let incoming_request = json.as_object().unwrap();
    let user_token = Token { id: 1, token: "aassdd".into()};

    if incoming_request.contains_key("id") {
        println!("{:?}", incoming_request.get("id").unwrap().to_string().parse::<i128>().unwrap());

        let mut crypt = Sha512::new();
        crypt.update(incoming_request.get("password").unwrap().to_string());
        let encr_pwd = format!("{:x}", crypt.finalize());

        println!("{:?}", encr_pwd);

    }

    Json::from(user_token)
}

//Handling registration
#[post("/auth/register", format = "json", data = "<json>")]
fn register(json: Json<Value>) -> Json<Token> {
    let incoming_request = json.as_object().unwrap();
    let user_token = Token { id: 1, token: "aassdd".into()};

    if incoming_request.contains_key("id") {
        println!("{:?}", incoming_request.get("id").unwrap().to_string().parse::<i128>().unwrap());

        let mut crypt = Sha512::new();
        crypt.update(incoming_request.get("password").unwrap().to_string());
        let encr_pwd = format!("{:x}", crypt.finalize());

        println!("{:?}", encr_pwd);

    }

    Json::from(user_token)
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![login, logout, register]).attach(CORS)
}