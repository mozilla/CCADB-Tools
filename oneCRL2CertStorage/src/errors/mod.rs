/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::From;
use std::io::Cursor;

error_chain! {
    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error);
//        Reqwest(reqwest::Error);
//        Infallible(std::convert::Infallible);
//        Json(serde_json::error::Error);
//        ASN1(simple_asn1::ASN1EncodeErr);
    }
}

impl std::convert::From<rkv::StoreError> for Error {
    fn from(err: rkv::StoreError) -> Self {
        format!("{:?}", err).into()
    }
}

//impl<'a> Responder<'a> for Error {
//    fn respond_to(self, _: &Request) -> std::result::Result<Response<'a>, Status> {
//        Ok(ResponseBuilder::new(Response::new())
//            .sized_body(Cursor::new(self.to_string()))
//            .status(Status::InternalServerError)
//            .finalize())
//    }
//}
