//! Small example application for Portier using the Rocket framework.

use log::error;
use rocket::{
    form::Form,
    get,
    http::{uri::Absolute, Status},
    launch, post,
    response::{content::Html, Redirect},
    routes, FromForm, State,
};

/// Struct used to deserialize form data for `POST /auth`.
#[derive(FromForm)]
struct AuthForm {
    email: String,
}

/// Struct used to deserialize form data for `POST /verify`.
#[derive(FromForm)]
struct VerifyForm {
    id_token: String,
}

/// Render a simple index page with a login form.
#[get("/")]
fn index() -> Html<&'static str> {
    Html(
        r#"
        <p>Enter your email address:</p>
        <form method="post" action="/auth">
          <input name="email" type="email">
          <button type="submit">Login</button>
        </form>
        "#,
    )
}

/// Handle the login form `POST /auth` request.
///
/// This creates a login session using `portier::Client::start_auth`, and redirects the browser to
/// complete the login.
#[post("/auth", data = "<form>")]
async fn auth(form: Form<AuthForm>, client: &State<portier::Client>) -> Result<Redirect, Status> {
    let url = client.start_auth(&form.email).await.map_err(|err| {
        error!("Portier start_auth error: {}", err);
        Status::InternalServerError
    })?;

    Ok(Redirect::to(Absolute::parse_owned(url.into()).unwrap()))
}

/// Handle the Portier response that arrives as a `POST /verify` request.
///
/// Once the broker has authenticated the user, the user agent is instructed to make this `POST`
/// request to us. The request contains a token we can verify using `portier::Client::verify`,
/// which checks that the signature on the token is correct, then extracts the email address
/// contained within.
///
/// Our example application renders a simple page showing that email address.
#[post("/verify", data = "<form>")]
async fn verify(
    form: Form<VerifyForm>,
    client: &State<portier::Client>,
) -> Result<Html<String>, Status> {
    let email = client.verify(&form.id_token).await.map_err(|err| {
        error!("Portier verify error: {}", err);
        Status::InternalServerError
    })?;

    Ok(Html(format!("<p>Verified email address {}!</p>", email)))
}

/// Rocket entry-point.
#[launch]
fn rocket() -> _ {
    let redirect_uri = "http://localhost:8000/verify".parse().unwrap();
    rocket::build()
        .mount("/", routes![index, auth, verify])
        .manage(portier::Client::new(redirect_uri))
}
