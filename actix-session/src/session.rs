use std::{
    cell::{Ref, RefCell},
    error::Error as StdError,
    mem,
    rc::Rc,
};

use actix_utils::future::{ready, Ready};
use actix_web::{
    body::BoxBody,
    dev::{Extensions, Payload, ServiceRequest, ServiceResponse},
    error::Error,
    FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError,
};
use derive_more::{Display, From};
use serde::{Deserialize, Serialize};

/// The primary interface to access and modify session state.
///
/// [`Session`] is an [extractor](#impl-FromRequest)—you can specify it as an input type for your
/// request handlers and it will be automatically extracted from the incoming request.
///
/// ```
/// use actix_session::Session;
///
/// async fn index(session: Session) -> actix_web::Result<&'static str> {
///     // access session data
///     if let Some(count) = session.get::<i32>("counter")? {
///         session.insert("counter", count + 1)?;
///     } else {
///         session.insert("counter", 1)?;
///     }
///
///     Ok("Welcome!")
/// }
/// # actix_web::web::to(index);
/// ```
///
/// You can also retrieve a [`Session`] object from an `HttpRequest` or a `ServiceRequest` using
/// [`SessionExt`].
///
/// [`SessionExt`]: crate::SessionExt
#[derive(Clone)]
pub struct Session(Rc<RefCell<SessionInner>>);

/// Status of a [`Session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    /// Session state has been updated - the changes will have to be persisted to the backend.
    Changed,

    /// The session has been flagged for deletion - the session cookie will be removed from
    /// the client and the session state will be deleted from the session store.
    ///
    /// Most operations on the session after it has been marked for deletion will have no effect.
    Purged,

    /// The session has been flagged for renewal.
    ///
    /// The session key will be regenerated and the time-to-live of the session state will be
    /// extended.
    Renewed,

    /// The session state has not been modified since its creation/retrieval.
    Unchanged,
}

impl Default for SessionStatus {
    fn default() -> SessionStatus {
        SessionStatus::Unchanged
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Display)]
pub enum UserType {
    Consumer,
    Producer,
    Guest,
    None,
}

impl Default for UserType {
    fn default() -> Self {
        UserType::None
    }
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct SessionState {
    user_id: String,
    user_type: UserType,
}

impl SessionState {
    pub fn new(user_id: String, user_type: UserType) -> Self {
        SessionState { user_id, user_type }
    }

    pub fn is_empty(&self) -> bool {
        self.user_id.is_empty()
    }

    pub fn user_id(&self) -> &String {
        &self.user_id
    }

    pub fn user_type(&self) -> &UserType {
        &self.user_type
    }
}

#[derive(Default)]
struct SessionInner {
    state: SessionState,
    status: SessionStatus,
}

impl Session {
    /// Set fields for the session's stored data
    pub fn set(&self, user_id: String, user_type: UserType) {
        let mut inner = self.0.borrow_mut();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.user_id = user_id;
            inner.state.user_type = user_type;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.borrow().state.is_empty()
    }

    pub fn get(&self) -> (String, UserType) {
        let s = self.0.borrow().state.clone();
        (s.user_id, s.user_type)
    }

    /// Returns session status.
    pub fn status(&self) -> SessionStatus {
        Ref::map(self.0.borrow(), |inner| &inner.status).clone()
    }

    /// Clear the session.
    pub fn clear(&self) {
        let mut inner = self.0.borrow_mut();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.user_id.clear();
            inner.state.user_type = UserType::None;
        }
    }

    /// Removes session both client and server side.
    pub fn purge(&self) {
        self.clear();
        self.0.borrow_mut().status = SessionStatus::Purged;
    }

    /// Renews the session key, assigning existing session state to new key.
    pub fn renew(&self) {
        let mut inner = self.0.borrow_mut();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Renewed;
        }
    }

    /// Adds the given key-value pairs to the session on the request.
    ///
    /// Values that match keys already existing on the session will be overwritten. Values should
    /// already be JSON serialized.
    pub(crate) fn set_session(req: &mut ServiceRequest, data: SessionState) {
        let session = Session::get_session(&mut *req.extensions_mut());
        let mut inner = session.0.borrow_mut();
        inner.state = data;
    }

    /// Returns session status and iterator of key-value pairs of changes.
    ///
    /// This is a destructive operation - the session state is removed from the request extensions
    /// typemap, leaving behind a new empty map. It should only be used when the session is being
    /// finalised (i.e. in `SessionMiddleware`).
    pub(crate) fn get_changes<B>(res: &mut ServiceResponse<B>) -> (SessionStatus, SessionState) {
        if let Some(s_impl) = res
            .request()
            .extensions()
            .get::<Rc<RefCell<SessionInner>>>()
        {
            let state = mem::take(&mut s_impl.borrow_mut().state);
            (s_impl.borrow().status.clone(), state)
        } else {
            (SessionStatus::Unchanged, SessionState::default())
        }
    }

    pub(crate) fn get_session(extensions: &mut Extensions) -> Session {
        if let Some(s_impl) = extensions.get::<Rc<RefCell<SessionInner>>>() {
            return Session(Rc::clone(s_impl));
        }

        let inner = Rc::new(RefCell::new(SessionInner::default()));
        extensions.insert(inner.clone());

        Session(inner)
    }
}

/// Extractor implementation for [`Session`]s.
///
/// # Examples
/// ```
/// # use actix_web::*;
/// use actix_session::Session;
///
/// #[get("/")]
/// async fn index(session: Session) -> Result<impl Responder> {
///     // access session data
///     if let Some(count) = session.get::<i32>("counter")? {
///         session.insert("counter", count + 1)?;
///     } else {
///         session.insert("counter", 1)?;
///     }
///
///     let count = session.get::<i32>("counter")?.unwrap();
///     Ok(format!("Counter: {}", count))
/// }
/// ```
impl FromRequest for Session {
    type Error = Error;
    type Future = Ready<Result<Session, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(Ok(Session::get_session(&mut *req.extensions_mut())))
    }
}

/// Error returned by [`Session::get`].
#[derive(Debug, Display, From)]
#[display(fmt = "{}", _0)]
pub struct SessionGetError(anyhow::Error);

impl StdError for SessionGetError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}

impl ResponseError for SessionGetError {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::new(self.status_code())
    }
}

/// Error returned by [`Session::insert`].
#[derive(Debug, Display, From)]
#[display(fmt = "{}", _0)]
pub struct SessionInsertError(anyhow::Error);

impl StdError for SessionInsertError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}

impl ResponseError for SessionInsertError {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        HttpResponse::new(self.status_code())
    }
}
