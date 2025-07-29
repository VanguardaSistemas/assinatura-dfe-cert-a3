# Assinatura de DFe com certificado A3 em NodeJS
Foi difícil encontrar como assinar um DFe utilizando certificado A3, então criei este repositório para ter um exemplo mais "direto ao ponto". No código, eu apenas adiciono a assinatura em documentos de NFe e MDFe, então seria necessário ajustar para as particularidades dos outros documentos.

Um agradecimento ao pessoal do [PeculiarVentures](https://github.com/peculiarventures) que criou e disponibilizou uma série de ferramentas para lidar com assinaturas, seja com certificado A1 ou A3.
Eles também tem um programa chamado [FortifyApp](https://fortifyapp.com/) que, teoricamente, faz o que este exemplo se propôe, porém de forma mais abrangente. Quando tentei usar, não tive sucesso, não lembro o motivo, mas deixo aqui só para o pessoal saber que existe.

No exemplo, utilizo duas bibliotecas do PeculiarVentures. [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11), para ler os certificados A3 e assinar. E [xmldsigjs](https://github.com/PeculiarVentures/xmldsigjs), para adicionar a assinatura e os transforms no arquivo XML dos DFes.

O node-webcrypto-p11 implementa a interface PKCS#11, então, teoricamente, toda DLL de smartcard ou pendrive token que utiliza esta interface irá funcionar.
Abaixo tem uma tabela com as principais DLLs utilizadas pelo emissores de certificado A3 no Brasil, retirada do site da [OOBJ](https://oobj.com.br/bc/quais-dlls-usadas-certificado-a3/):

| Modelo | DLL |
| :---: | :---: |
| Token iKey 2032 | C:\Windows\system32\dkck201.dll |
| Token ePassNG 2000 | C:\Windows\system32\ngp11v211.dll |
| Token ePass2003 | C:\Windows\system32\eps2003csp11.dll |
| Cartão Safesign + Leitora Perto | C:\Windows\system32\aetpkss1.dll |
| eToken Aladdin | C:\Windows\system32\etpkcs11.dll |
| SafeWeb IntelCav | C:\Windows\system32\cmp11.dll |
| Certisign Cosmo Obethur Technologies | C:\Windows\System32\OcsCryptoki.dll |
| Gemalto x86 | C:\Program Files (x86)\Gemalto\IDGo 800 PKCS11\IDPrimePKCS11.dll |
| Gemalto x64 | C:\Program Files\Gemalto\IDGo 800 PKCS11\IDPrimePKCS1164.dll |

Lembrando que não sou especialista no assunto, esse código foi um junção de vários pequenos códigos que fui encontrando em minhas pesquisas, mas o mais importante é que funciona, pelo menos para o meu caso de uso. Talvez, estritamente, não seja útil fazer um copia e cola, porém espero que sirva ao menos de inspiração.

O meu programa faz autorização de NFes e MDFes pela Web. Geralmente, esse tipo de programa na Web, não faz uso de certificados A3, porém como tínhamos clientes legado que usavam, tivemos que bolar uma solução.
Não encontrei nenhum jeito de assinar com o certificado A3, sem que tenha que instalar um .exe no desktop do cliente. Então criei um programa em nodeJS que recebe o arquivo XML e os dados necessários por um endpoint, assino e retorno o XML assinado. Compilei o .exe com o [Electron](https://www.electronjs.org/).

Abaixo está o código para assinatura e inclusão da tag no XML, testado apenas no Windows:
```
/**
 * Assina um XML com certificado A3
 * @param {string} xml - XML a ser assinado
 * @param {object} empresa - Dados da empresa
 * @param {string} tagId - ID da tag usada para assinatura
 * @returns {Promise<string>} XML assinado
 */
async function signXml(xml, empresa, tagId) {
  try {
    xmldsigjs.Application.setEngine(
      "PKCS11",
      new Crypto({
        library: empresa.dllPath, // DLL do smartcard ou pendrive token
        slot: 0,
        sessionFlags: 4, // SERIAL_SESSION
        pin: empresa.senhaCerti, // Senha do certificado
      })
    );
    changeXmlDSigPrefix(""); // Remove o prefixo padrão "ds:"

    const cryptoP11 = xmldsigjs.Application.crypto;

    let publicCert;
    let publicCertId;
    const certIndexes = await cryptoP11.certStorage.keys();
    for (const index of certIndexes) {
      try {
        // Esse try/catch é para ignorar certificados inúteis, para o objetivo aqui, do repositório do Windows
        const cert = await cryptoP11.certStorage.getItem(index);
        if (cert.serialNumber.toLowerCase() === empresa.numeroSerieCerti.toLowerCase()) {
          publicCert = cert;
          publicCertId = index.split("-")[2];
          break;
        }
      } catch (err) {}
    }
    const subjectArr = publicCert.x509.subject.split(",");
    if (!subjectArr.length) throw new Error("Splited Array do Subject do certificado está vazio");

    const subjectCN = subjectArr.find((text) => text.toUpperCase().includes("CN="));
    if (!subjectCN) throw new Error("Não foi possível capturar o SubjectCN do certificado");

    const cnpj = subjectCN.split(":")[1];
    if (!cnpj) throw new Error("Não foi possível capturar o CNPJ do certificado");
    if (cnpj !== empresa.cpfCnpj) {
      throw new Error(`Certificado (${subjectCN.split("=")[1]}) não pertence à empresa com CNPJ: ${empresa.cpfCnpj}`);
    }

    let privateKey;
    const keyIndexes = await cryptoP11.keyStorage.keys();
    for (const index of keyIndexes) {
      const [type, handle, id] = index.split("-");
      if (type === "private" && id.toLowerCase() === publicCertId.toLowerCase()) {
        try {
          // Esse try/catch é para ignorar certificados inúteis, para o objetivo aqui, do repositório do Windows
          privateKey = await cryptoP11.keyStorage.getItem(index);
          break;
        } catch (err) {}
      }
    }

    let xmlDom = xmldsigjs.Parse(xml); // Convertendo o arquivo XML para o padrão XML DOM
    const signedXml = new xmldsigjs.SignedXml();

    const publicCertRaw = await cryptoP11.certStorage.exportCert("raw", publicCert);
    const x509Data = new xmldsigjs.KeyInfoX509Data();
    x509Data.AddCertificate(new xmldsigjs.X509Certificate(publicCertRaw));
    signedXml.XmlSignature.KeyInfo.Add(x509Data); // Adicionando certificado público para incluir na assinatura

    privateKey.algorithm.name = "RSASSA-PKCS1-v1_5"; // Algoritmo de assinatura
    privateKey.algorithm.hash = { name: "SHA-1" };

    const signature = await signedXml.Sign(
      privateKey.algorithm,
      privateKey, // key
      xmlDom, // document
      { references: [{ uri: `#${tagId}`, hash: "SHA-1", transforms: ["enveloped", "c14n"] }] }
    );

    let tagToAddSig; // Tag em que será adicionada a assinatura. Não confundir com a tag assinada
    if (xml.includes("infNFe")) tagToAddSig = "NFe";
    if (xml.includes("infMDFe")) tagToAddSig = "MDFe";
    if (xml.includes("infEvento")) tagToAddSig = "evento"; // Precisa vir primeiro que o eventoMDFe, pq ele tbm tem a tag infEvento
    if (xml.includes("eventoMDFe")) tagToAddSig = "eventoMDFe";

    const nfeTag = xmlDom.getElementsByTagName(tagToAddSig);
    nfeTag[0].appendChild(signature.GetXml());
    // xmlDom.documentElement.appendChild(signature.GetXml());

    const xmlWithSig = new XMLSerializer().serializeToString(xmlDom); // Convertendo o XML de volta para string
    // const xmlWithSig = signedXml.toString();

    // Verificação da assinatura
    let doc = xmldsigjs.Parse(xmlWithSig);
    let sigVer = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

    let sigVerXml = new xmldsigjs.SignedXml(doc);
    sigVerXml.LoadXml(sigVer[0]);

    const status = await sigVerXml.Verify();
    if (!status) throw new Error("Assinatura não é válida");

    fs.writeFile("./lastXmlSigned.xml", xmlWithSig, (err) => err && console.error(err)); // Para debug da assinatura se necessário
    return xmlWithSig;
  } catch (error) {
    throw error;
  }
}

/**
 * ALtera o prefixo das tags adicionadas. O XMLDSig adiciona automaticamente o prefixo "ds:"
 * @param {string} prefix
 */
function changeXmlDSigPrefix(prefix) {
  xmldsigjs.XmlSignature.DefaultPrefix = prefix;
  for (const key in xmldsigjs) {
    const object = xmldsigjs[key];
    if (object.namespaceURI === xmldsigjs.XmlSignature.NamespaceURI) {
      object.prefix = prefix;
    }
    for (const i in object.items) {
      const item = object.items[i];
      if (item.namespaceURI === xmldsigjs.XmlSignature.NamespaceURI) {
        item.prefix = prefix;
      }
    }
  }
}
```
