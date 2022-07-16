import os from 'os';
import fs from 'fs/promises';
import UglifyJS from 'uglify-js';
import jsonData from '../package.json' assert { type: 'json' };

const outputPath = `dist/${jsonData['version']}`;

try {
    await fs.mkdir(outputPath);
} catch {
}

const [database, connection, encryption] = await Promise.all([
    fs.readFile('database.js', 'utf8'),
    fs.readFile('connection.js', 'utf8'),
    fs.readFile('encryption.js', 'utf8')
]);

await Promise.all([
    fs.writeFile(`${outputPath}/database.min.js`, UglifyJS.minify(database).code),
    fs.writeFile(`${outputPath}/connection.min.js`, UglifyJS.minify(connection).code),
    fs.writeFile(`${outputPath}/encryption.min.js`, UglifyJS.minify(encryption).code),
    fs.writeFile(`${outputPath}/bundle.js`, UglifyJS.minify({ 'database.js': database, 'connection.js': connection, 'encryption.js': encryption }).code)
]);
