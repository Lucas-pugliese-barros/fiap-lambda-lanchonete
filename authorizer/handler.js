import { Signer } from "@aws-sdk/rds-signer";
import { Client } from 'pg';

async function createAuthToken() {
    const dbinfo = {
        hostname: process.env.ProxyHostName,
        port: process.env.Port,
        username: process.env.DBUserName,
        region: process.env.AWS_REGION,
    };

    const signer = new Signer(dbinfo);
    return await signer.getAuthToken();
}

async function dbOps(cpf) {
    const token = await createAuthToken();
    const connectionConfig = {
        host: process.env.ProxyHostName,
        user: process.env.DBUserName,
        password: token,
        database: process.env.DBName,
        port: process.env.Port || 5432,
        ssl: { rejectUnauthorized: false }
    };

    const client = new Client(connectionConfig);
    await client.connect(); // Conecta ao banco de dados


    // const res = await client.query('SELECT cpf FROM cliente WHERE cpf = $1', [cpf]);
    await client.end();

    return '12345678900'
    // return res.rows.length > 0 ? res.rows[0].cpf : null;
}

exports.authorizer = async function (event) {
    const token = event.authorizationToken.toLowerCase();
    const methodArn = event.methodArn;

    switch (token) {
        case 'allow':
            return generateAuthResponse('user', 'Allow', methodArn);
        case token != null:
            const result = await dbOps(token);
            if (result === token) {
                return generateAuthResponse('user', 'Allow', methodArn);
            } else {
                return generateAuthResponse('user', 'Deny', methodArn);
            }
        default:
            return generateAuthResponse('user', 'Deny', methodArn);
    }
}

function generateAuthResponse(principalId, effect, methodArn) {
    const policyDocument = generatePolicyDocument(effect, methodArn);

    return {
        principalId,
        policyDocument
    }
}

function generatePolicyDocument(effect, methodArn) {
    if (!effect || !methodArn) return null;

    const policyDocument = {
        Version: '2012-10-17',
        Statement: [{
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: methodArn
        }]
    };

    return policyDocument;
}
