import {Signer} from "@aws-sdk/rds-signer";
import mysql from 'mysql2/promise';

async function createAuthToken() {
    const dbinfo = {

        hostname: process.env.ProxyHostName,
        port: process.env.Port,
        username: process.env.DBUserName,
        region: process.env.AWS_REGION,

    }

    const signer = new Signer(dbinfo);
    return await signer.getAuthToken();
}

async function dbOps(cpf: string)   {
    const token = await createAuthToken();
    let connectionConfig = {
        host: process.env.ProxyHostName,
        user: process.env.DBUserName,
        password: token,
        database: process.env.DBName,
        ssl: 'Amazon RDS'
    }

    const conn = await mysql.createConnection(connectionConfig);
    const [res,] = await conn.execute('select count(*) from clients where cpf = ?', cpf);
    return res;

}

exports.authorizer = async function (event) {
    const token = event.authorizationToken.toLowerCase();
    const methodArn = event.methodArn;

    if (token !== null) {
        return generateAuthResponse('user', 'Allow', methodArn);
    }

    const result = await dbOps(token);

    if (result !== undefined) {
        return generateAuthResponse('user', 'Allow', methodArn);
    } else {
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
    if (!effect || !methodArn) return null

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