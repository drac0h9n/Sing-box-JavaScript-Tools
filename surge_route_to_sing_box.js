const fs = require('fs');

if (process.argv.length !== 4) {
    console.error('Usage: node surge_route_to_sing_box.js <inputFile> <outputFile>');
    process.exit(1);
}

const inputFile = process.argv[2];
const outputFile = process.argv[3];

// 初始化数据结构
const rules = {
    domain: [],
    domain_suffix: [],
    domain_keyword: [],
};

// 解析输入文件
fs.readFile(inputFile, 'utf8', (err, data) => {
    if (err) {
        console.error(`Error reading input file: ${err.message}`);
        process.exit(1);
    }

    const lines = data.split('\n').map(line => line.trim()).filter(line => line);

    for (const line of lines) {
        const parts = line.split(',');
        if (parts.length !== 3) {
            console.warn(`Skipping invalid line: ${line}`);
            continue;
        }

        const [type, value, service] = parts;
        if (service !== 'GPT SERVICE') {
            console.warn(`Skipping unsupported service: ${service}`);
            continue;
        }

        switch (type.toUpperCase()) {
            case 'DOMAIN':
                rules.domain.push(value);
                break;
            case 'DOMAIN-SUFFIX':
                rules.domain_suffix.push(value);
                break;
            case 'DOMAIN-KEYWORD':
                rules.domain_keyword.push(value);
                break;
            default:
                console.warn(`Skipping unknown type: ${type}`);
        }
    }

    // 构建最终的 JSON 对象
    const output = {
        version: 3,
        rules: [rules],
    };

    // 写入输出文件
    fs.writeFile(outputFile, JSON.stringify(output, null, 4), 'utf8', err => {
        if (err) {
            console.error(`Error writing output file: ${err.message}`);
            process.exit(1);
        }

        console.log(`Successfully written to ${outputFile}`);
    });
});
