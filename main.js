const express = require('express');
const cors = require('cors');
const moment = require('moment');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const CryptoJS = require('crypto-js');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const LOGS_FILE = path.join(__dirname, 'logs.txt');
const ALLOWED_ORIGINS = /\.slavik00\.ru$/; // Измените этот URL для настройки CORS

// app.use(cors({ origin: ALLOWED_ORIGIN }));
// app.use(cors());
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.test(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
}));
app.use(express.json());

// Функция записи логов
async function logAction(action, username) {
    const logEntry = `${moment().format('YYYY-MM-DD HH:mm:ss')} - ${action} - ${username}\n`;
    await fs.appendFile(LOGS_FILE, logEntry);
}

// Чтение пользователей
async function readUsers() {
    try {
        const data = await fs.readFile(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return {};
    }
}

// Запись пользователей
async function writeUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 4));
}

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    const users = await readUsers();
    if (users[username]) {
        return res.status(400).json({ message: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = uuidv4();
    
    users[username] = {
        password: hashedPassword,
        token,
        data: {},
    };
    
    await writeUsers(users);
    await logAction('REGISTER', username);
    res.json({ message: 'User registered successfully', token });
});

// Авторизация
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = await readUsers();
    
    if (!users[username] || !(await bcrypt.compare(password, users[username].password))) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    await logAction('LOGIN', username);
    res.json({ message: 'Login successful', token: users[username].token });
});

// Получение данных пользователя
app.get('/api/user/data', async (req, res) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    
    const users = await readUsers();
    const user = Object.keys(users).find(u => users[u].token === token);
    
    if (!user) {
        return res.status(401).json({ message: 'Invalid token' });
    }
    
    res.json({ data: users[user].data });
});

// Обновление данных пользователя
app.post('/api/user/data', async (req, res) => {
    const token = req.headers.authorization;
    const { data } = req.body;
    
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    
    const users = await readUsers();
    const user = Object.keys(users).find(u => users[u].token === token);
    
    if (!user) {
        return res.status(401).json({ message: 'Invalid token' });
    }
    
    users[user].data = data;
    await writeUsers(users);
    await logAction('UPDATE_DATA', user);
    
    res.json({ message: 'Data updated successfully' });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
