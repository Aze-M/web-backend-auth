#[macro_use]
extern crate rocket;

use rocket::http::{ContentType, Header, Status};
use rocket::{Request, Response};

use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

use rocket::fairing::{Fairing, Info, Kind};
use rocket::serde::json::Json;
use rocket::serde::json::*;
use rocket::serde::{Deserialize, Serialize};
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
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS",
        ));
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

//general Functions

fn generateToken(name: String) -> Token {
    //Make a random token
    let mut crypt = Sha512::new();
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
    crypt.update(rand_string);

    let user_token = Token {
        id: 1,
        token: format!("{:x}", crypt.finalize()),
    };

    return user_token;
}

//Handling logins
#[post("/auth/login", format = "json", data = "<json>")]
fn login(json: Json<Value>) -> Result<Json<Token>, Status> {
    //Open the config file
    // let file: File = File::open("config.json").unwrap();
    // let config: Value = serde_json::from_reader(file).unwrap();

    let incoming_request = json.as_object().unwrap();
    let user_token = generateToken(incoming_request.get("name").unwrap().to_string());

    if !incoming_request.contains_key("name") {
        return Err(Status::BadRequest);
    }

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
