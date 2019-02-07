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

  pip install -e .[test,docs]
  pserve config/service.ini --reload

Generate dockey,dockeys::

  python -c "from libnacl.sign import Signer; k=Signer(); print 'private:', k.hex_seed(), '\npublic:', k.hex_vk()"
