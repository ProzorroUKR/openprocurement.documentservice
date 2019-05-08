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

  python -c "from libnacl.sign import Signer; k=Signer(); print 'private:', k.hex_seed(), '\npublic:', k.hex_vk()"

Generate docs::

  python docs.py
  cd docs && make html
