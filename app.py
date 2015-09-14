#!/usr/bin/env python3
import os
import logging
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s')
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from time import time
from uuid import uuid1
import json

import tornado.web


sessions = {}


class BaseHandler(tornado.web.RequestHandler):

    session = None

    def initialize(self):
        if self.current_user:
            # ha van bejelentkezett felhasználó, akkor kiolvassuk a sessiont a memóriából
            uid = self.current_user
            self.session = sessions.get(uid)
        else:
            self.session = None

    def get_current_user(self):
        uid = self.get_cookie("user")
        if uid:
            if not sessions.get(uid):
                # ha nincs session, akkor nem számít bejelentkezett felhasználónak,
                # mivel a munkamenet csak a memóriában van tárolva
                return None
            logging.info("user_id: " + uid)
        return uid


class MeHandler(BaseHandler):

    def get(self):
        if not self.current_user:
            # nincs bejelentkezve
            self.set_status(401)
            return
        user = self.session.get("user", {}).copy()
        # a jelszót nem adjuk ki a válaszban
        del user["password"]
        self.write(json.dumps(user))

    def post(self):
        try:
            if not self.request.body:
                raise ValueError
            data = json.loads(self.request.body.decode('utf-8'))
            email = data["email"]
            if self.current_user:
                for session in sessions.values():
                    logging.debug(session["user"])
                    if email == session["user"]["email"]:
                        self.set_status(406)
                        return
            password = data["pswd"]
        except ValueError:
            # helytelen JSON
            self.set_status(400)
            return
        except KeyError:
            # hiányzó paraméter
            self.set_status(400)
            return
        # bejelentkezés
        uid = str(uuid1())
        user = {"uuid": uid, "email": email, "password": password, "created": int(time())}
        self.set_cookie("user", uid)
        sessions[uid] = {"user": user.copy(), "docs": {}, "submit_token": None}
        # a jelszót nem adjuk ki a válaszban
        del user["password"]
        self.set_status(201)
        self.write(json.dumps(user))


class DocHandler(BaseHandler):

    def get(self):
        if not self.current_user:
            # nincs bejelentkezve
            self.set_status(401)
            return
        docs = self.session.get("docs", {})
        self.write(json.dumps(list(docs.values())))

    def post(self):
        if not self.current_user:
            # nincs bejelentkezve
            self.set_status(401)
            return
        if not self.request.files:
            self.set_status(400)
            return
        docs = self.session.get("docs", {})
        try:
            for name, file in self.request.files.items():
                file = file[0]
                upload_path = os.path.join(os.path.dirname(__file__), os.path.abspath("uploads"), self.current_user)
                os.makedirs(upload_path, exist_ok=True)
                dest = os.path.join(upload_path, file.get("filename"))
                with open(dest, "wb") as f:
                    f.write(file.get("body"))
                uuid = str(uuid1())
                docs[uuid] = {
                    "uuid": uuid,
                    "name": name,
                    "size": len(file.get("body")),
                    "created": int(time()),
                }
        except IOError:
            self.set_status(500)
            return
        self.session["docs"] = docs
        self.set_status(201)

    def delete(self):
        if not self.current_user:
            # nincs bejelentkezve
            self.set_status(401)
            return
        try:
            if not self.request.body:
                raise ValueError
            data = json.loads(self.request.body.decode('utf-8'))
            if 0 == len(data):
                return
            for item in data:
                uuid = item.get("uuid")
                if not uuid:
                    raise ValueError
                del self.session["docs"][uuid]
        except KeyError:
            # helytelen JSON
            self.set_status(400)
            return
        except ValueError:
            # helytelen JSON
            self.set_status(400)
            return


class SubmitHandler(BaseHandler):

    def get(self):
        if not self.current_user:
            # nincs bejelentkezve
            self.set_status(401)
            return
        token = str(uuid1())
        self.session["submit_token"] = token
        self.write(json.dumps({"uuid": token}))

    def post(self):
        if not self.current_user:
            # nincs bejelentkezve
            self.set_status(401)
            return
        try:
            if not self.request.body:
                raise KeyError
            submit_token = self.session.get("submit_token")
            if not submit_token:
                raise KeyError
            data = json.loads(self.request.body.decode('utf-8'))
            if data.get("uuid") != submit_token:
                raise KeyError
            # a felhasználót kijelentkeztetjük
            try:
                del sessions[self.current_user]
            except KeyError:
                pass
            self.clear_cookie("user")
        except ValueError:
            # helytelen JSON
            self.set_status(400)
            return
        except KeyError:
            # hiányzó paraméter
            self.set_status(400)
            return


class LogoutHandler(BaseHandler):

    def get(self):
        if not self.current_user:
            # nincs bejelentkezve
            self.set_status(401)
            return
        # kijelentkezés
        try:
            del sessions[self.current_user]
        except KeyError:
            pass
        self.clear_cookie("user")


handlers = [
    ("/me", MeHandler),
    ("/doc", DocHandler),
    ("/submit", SubmitHandler),
    ("/logout", LogoutHandler),
]

application = tornado.web.Application(handlers, **{"autoreload": True, "xsrf_cookies": False})


def main(args):
    levels = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
    if args.verbosity >= len(levels):
        raise IndexError("Verbosity must be 0 <= n < 4")
    logging.getLogger().setLevel(levels[args.verbosity])
    application.listen(args.port, args.host)
    logging.info("listening on {host}:{port}...".format(host=args.host, port=args.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-p", "--port", type=int,
                        default=8090,
                        help="override port")
    parser.add_argument("-s", "--host", type=str,
                        default="0.0.0.0",
                        help="override host")
    parser.add_argument("-v", dest="verbosity", action="count", default=0,
                        help="Control verbosity")
    args = parser.parse_args()
    main(args)
