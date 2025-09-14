const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const port = process.env.PORT || 5173;
const secret = process.env.SECRET_KEY || 'hjfgjhf';

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./books.db");

db.serialize(() => {
    db.run(
        "create table if not exists roles(id integer primary key autoincrement, role text unique)"
    );
    db.run(
        "create table if not exists users(id integer primary key autoincrement, username text unique, email text unique, password text, roleid integer, foreign key(roleid) references roles(id))"
    );
    db.run("insert or ignore into roles(role) values('admin')");
    db.run("insert or ignore into roles(role) values('user')");
    db.run(
        "create table if not exists images(id integer primary key autoincrement, image_path text not null unique)"
    );
    db.run(
        "create table if not exists books(id integer primary key autoincrement, title text, author text, genre text, description text, image_id integer, foreign key(image_id) references images(id))"
    );
})

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body; 
    
        if (!username || !email || !password) {
        return res.status(400).json({ error: "Все поля обязательны для заполнения." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    db.get("select count(*) as count from users", (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        const isFirstUser = row.count == 0; 
        const roleName = isFirstUser ? "admin" : "user";

        db.get("select id from roles where role=?", [roleName], (err, role) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            db.run(
                "insert into users(username, email, password, roleid) values(?,?,?,?)",
                [username, email, hashedPassword, role.id],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    return res
                        .status(201)
                        .json({ message: "Пользователь зарегистрирован" });
                }
            );
        });
    });
});

app.post("/login", async (req, res) => {
    const { username, email, password } = req.body;
    db.get(
        "select * from users where username=? or email=?",
        [username, email],
        async (err, user) => {
            if (err || !user) {
                return res.status(400).json({ error: err.message });
            }
            const isPasswordValid = await bcrypt.compare(
                password,
                user.password
            );
            if (!isPasswordValid) {
                return res.status(400).json({ message: "Неверный пароль" });
            }
            db.get(
                "select role from roles where id=?",
                [user.roleid],
                async (err, role) => {
                    if (err) {
                        return res.status(400).json({ error: err.message });
                    }
                    const token = jwt.sign(
                        {
                            id: user.id,
                            username: user.username,
                            role: role.role,
                        },
                        secret,
                        { expiresIn: "10m" }
                    );
                    res.json({
                        token,
                        user: {
                            id: user.id,
                            username: user.username,
                            role: role.role,
                        },
                    });
                }
            );
        }
    );
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    const token = authHeader && authHeader.split(" ")[1];
    if(!token) {
        return res.status(401).json({message: "Токен не обнаружен"});
    }
    jwt.verify(token, secret, (err, user) => {
        if(err) {
            return res.status(403).json({message: "Невалидный токен"});
        }

        req.user = user;
        next();
    })
}

app.get("/books", authenticateToken, async (req, res) => {
    db.all(
        `SELECT books.title, books.author, images.image_path AS image 
         FROM books 
         LEFT JOIN images ON books.image_id = images.id`,
        (err, books) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            return res.json(books);
        }
    );
});
app.get("/books/:id", authenticateToken, async (req, res) => {
    const bookId = req.params.id;

    db.get("select * from books where id = ?", [bookId], (err, book) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!book) {
            return res.status(404).json({ message: "Книга не найдена" });
        }
        return res.json(book);
    });
});

app.post('/create', authenticateToken, async (req, res) => {
    const { title, author, genre, description, image } = req.body;

    if (req.user && req.user.role === 'admin') {
        try {
            // Проверка, существует ли изображение
            const existingImage = await new Promise((resolve, reject) => {
                db.get("SELECT id FROM images WHERE image_path = ?", [image], (err, row) => {
                    if (err) return reject(err);
                    resolve(row);
                });
            });

            let imageId;

            if (existingImage) {
                imageId = existingImage.id;
            } else {
                imageId = await new Promise((resolve, reject) => {
                    db.run("INSERT INTO images (image_path) VALUES (?)", [image], function(err) {
                        if (err) return reject(err);
                        resolve(this.lastID); 
                    });
                });
            }

            await new Promise((resolve, reject) => {
                db.run(
                    "INSERT INTO books (title, author, genre, description, image_id) VALUES (?, ?, ?, ?, ?)",
                    [title, author, genre, description, imageId],
                    function(err) {
                        if (err) return reject(err);
                        resolve();
                    }
                );
            });

            res.status(201).json({ message: "Книга добавлена" });
        } catch (error) {
            console.error("Ошибка при добавлении книги:", error);
            res.status(500).json({ message: "Ошибка при добавлении книги" });
        }
    } else {
        res.status(403).json({ message: "У вас нет прав для добавления книги" });
    }
});

app.put('/edit/:id', authenticateToken, async (req, res) => {
    const bookId = req.params.id;
    const { title, author, genre, description, image } = req.body;

    if (req.user && req.user.role === 'admin') {
        if (!title || !author || !genre || !description || !image) {
            return res.status(400).json({ message: "Все поля обязательны для заполнения" });
        }

        try {
            const existingImage = await new Promise((resolve, reject) => {
                db.get("SELECT id FROM images WHERE image_path = ?", [image], (err, row) => {
                    if (err) return reject(err);
                    resolve(row);
                });
            });

            let imageId;

            if (existingImage) {
                imageId = existingImage.id;
            } else {
                imageId = await new Promise((resolve, reject) => {
                    db.run("INSERT INTO images (image_path) VALUES (?)", [image], function(err) {
                        if (err) return reject(err);
                        resolve(this.lastID);
                    });
                });
            }

            await new Promise((resolve, reject) => {
                db.run(
                    "UPDATE books SET title = ?, author = ?, genre = ?, description = ?, image_id = ? WHERE id = ?",
                    [title, author, genre, description, imageId, bookId],
                    function(err) {
                        if (err) return reject(err);
                        resolve();
                    }
                );
            });

            res.status(200).json({ message: "Книга обновлена" });
        } catch (error) {
            res.status(500).json({ message: "Ошибка при редактировании книги" });
        }
    } else {
        res.status(403).json({ message: "У вас нет прав для редактирования данных книги" });
    }
});

app.delete("/books/:id", authenticateToken, async (req, res) => {
    if (req.user.role === "admin") {
        const { id } = req.params;

        db.run("DELETE FROM books WHERE id = ?", [id], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (this.changes === 0) {
                return res.status(404).json({ message: "Книга не найдена" });
            }

            return res.json({ message: "Книга удалена" });
        });
    } else {
        return res.status(403).json({ message: "Доступ только для администраторов" });
    }
});

app.listen(port, () => 
    console.log(`Сервер запущен по адресу http://localhost:${port}`)
);