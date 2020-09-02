.. image:: https://travis-ci.org/ProzorroUKR/openprocurement.documentservice.svg?branch=master
    :target: https://travis-ci.org/ProzorroUKR/openprocurement.documentservice

.. image:: https://coveralls.io/repos/github/ProzorroUKR/openprocurement.documentservice/badge.svg?branch=master
    :target: https://coveralls.io/github/ProzorroUKR/openprocurement.documentservice?branch=master

.. image:: //readthedocs.org/projects/prozorro-openprocurementdocumentservice/badge/?version=latest
    :target: https://prozorro-openprocurementdocumentservice.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

Development install
-------------------
Use following command for install and run server::

  pip install -r requirements.txt -e .[test,docs]
  gunicorn -k gevent --paste config/service.ini --reload

Generate dockey,dockeys::

  from nacl.encoding import HexEncoder
  from nacl.signing import SigningKey
  k = SigningKey.generate()
  private, public = k.encode(encoder=HexEncoder).decode(), k.verify_key.encode(encoder=HexEncoder).decode()
  print ('private: {}\npublic: {}'.format(private, public))

Generate docs::

  python docs.py
  cd docs && make html

Notes:

JOURNAL_PREFIX env var should be the same as for https://git.prozorro.gov.ua/cdb/ds_reports service
