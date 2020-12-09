from base64 import b64decode
from defusedxml.ElementTree import fromstring as xmlparse
from xml.etree.ElementTree import Element as XmlElement

__all__ = ['parse']

def xml_transform(element: XmlElement, ids):
    """Transform the given apple XML into an hierarchy based on
    python specific objects(list, dictionary). It also requires a
    dictionary(ids) for searching the referenced objects.
    """
    if 'IDREF' in element.attrib:
        assert element.tag in ['string', 'integer']
        assert element.attrib['IDREF'] in ids
        data = ids[element.attrib['IDREF']]
    else:
        data = element.text

    if element.tag == 'true':
        return True
    if element.tag == 'false':
        return False
    if element.tag == 'data':
        return b64decode(data)
    if element.tag == 'string':
        return data if data != None else ''
    if element.tag == 'integer':
        if data == None:
            print("WARNING int NULL", file=sys.stderr)
            return None
        return int(data,
            16 if  data[:2].lower() == '0x' else
            8 if data[0] == '0' else 10)
    if element.tag == 'dict':
        result = {}
        key = None
        for subelement in element:
            if subelement.tag == 'key':
                assert type(subelement.text) == str
                key = subelement.text
            elif key != None:
                result[key] = xml_transform(subelement, ids)
                key = None
        return result
    if element.tag == 'array':
        return [xml_transform(subelement, ids) for subelement in element]
    print("WARNING unkown tag {}".format(v.tag), file=sys.stderr)


def get_xml_ids(element: XmlElement, ids: dict):
    """Extract elements with ID attributes from given XML and inserts them into
    the ids dictionary.
    """
    if 'ID' in element.attrib:
        assert element.tag in ['string', 'integer', 'data']
        assert element.text != None or element.tag == 'string'
        assert element.attrib['ID'] not in ids
        ids[element.attrib['ID']] = element.text
    if element.tag in ['dict', 'array']:
        for subelement in element:
            get_xml_ids(subelement, ids)


def parse(data: str):
    """Parse apple XML from given string.
    """
    while data[-1] == '\0':
        data = data[:-1]

    ids = {}
    xml = xmlparse(data)
    get_xml_ids(xml, ids)
    return xml_transform(xml, ids)
