..
    **************************************************
    *                                                *
    *   Automatically generated file, do not edit!   *
    *                                                *
    **************************************************

.. _amdgpu_synid_gfx8_vdata_629a92:

vdata
=====

Image data to store by an *image_store* instruction.

*Size:* depends on :ref:`dmask<amdgpu_synid_dmask>` and :ref:`d16<amdgpu_synid_d16>`:

* :ref:`dmask<amdgpu_synid_dmask>` may specify from 1 to 4 data elements. Each data element occupies either 32 bits or 16 bits, depending on :ref:`d16<amdgpu_synid_d16>`.
* :ref:`d16<amdgpu_synid_d16>` has different meanings for GFX8.0 and GFX8.1:

  * For GFX8.0, this modifier does not affect the size of data elements in registers. Values in registers are stored in low 16 bits, high 16 bits are unused. There is no packing.
  * Starting from GFX8.1, this modifier specifies that values in registers are packed; each value occupies 16 bits.

*Operands:* :ref:`v<amdgpu_synid_v>`
