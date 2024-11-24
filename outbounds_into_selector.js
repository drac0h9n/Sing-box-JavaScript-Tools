/*
输入
{
  "outbounds": [
    {
      "tag": "tag1"
    },
    {
      "tag": "tag2"
    },
    {
      "tag": "tag3"
    }
  ]
}

输出
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": [
        "tag1",
        "tag2",
        "tag3"
      ],
      "default": "tag1"
    },
    {
      "tag": "tag1"
    },
    {
      "tag": "tag2"
    },
    {
      "tag": "tag3"
    }
  ]
}
*/

const fs = require('fs');

// 获取命令行参数
const args = process.argv.slice(2);

if (args.length !== 2) {
    console.error('用法: node outbounds_into_selector.js input.json output.json');
    process.exit(1);
}

const [inputFile, outputFile] = args;

try {
    // 读取输入文件并解析
    const inputContent = fs.readFileSync(inputFile, 'utf8');
    const inputData = JSON.parse(inputContent, (key, value) => value);

    // 深复制一份原始结构用于保留字段顺序
    const outputData = JSON.parse(JSON.stringify(inputData));

    // 检查并处理 outbounds 字段
    if (Array.isArray(inputData.outbounds)) {
        const tags = inputData.outbounds.map(outbound => outbound.tag);

        // 构造 selector 结构
        const selector = {
            type: 'selector',
            tag: 'select',
            outbounds: tags,
            default: tags[0] || null
        };

        // 替换 outbounds 中的内容
        outputData.outbounds = [selector, ...inputData.outbounds];
    }

    // 将修改后的内容写入输出文件
    fs.writeFileSync(outputFile, JSON.stringify(outputData, null, 2), 'utf8');
    console.log(`处理完成，输出文件已保存到 ${outputFile}`);
} catch (error) {
    console.error(`处理失败: ${error.message}`);
    process.exit(1);
}