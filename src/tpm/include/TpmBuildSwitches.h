/******************************************************************************************************************/
/*                                                                                                                */
/*                                                                                                                */
/*  Licenses and Notices                                                                                          */
/*                                                                                                                */
/*  1.  Copyright Licenses:                                                                                       */
/*     Trusted Computing Group (TCG) grants to the user of the source code in this specification (the             */
/*     "Source Code") a worldwide, irrevocable, nonexclusive, royalty free, copyright license to                  */
/*     reproduce, create derivative works, distribute, display and perform the Source Code and                    */
/*     derivative works thereof, and to grant others the rights granted herein.                                   */
/*     The TCG grants to the user of the other parts of the specification (other than the Source Code)            */
/*     the rights to reproduce, distribute, display, and perform the specification solely for the purpose         */
/*     of developing products based on such documents.                                                            */
/*                                                                                                                */
/*  2.  Source Code Distribution Conditions:                                                                      */
/*     Redistributions of Source Code must retain the above copyright licenses, this list of conditions           */
/*     and the following disclaimers.                                                                             */
/*     Redistributions in binary form must reproduce the above copyright licenses, this list of                   */
/*     conditions and the following disclaimers in the documentation and/or other materials provided              */
/*     with the distribution.                                                                                     */
/*                                                                                                                */
/*  3.  Disclaimers:                                                                                              */
/*     THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF LICENSE OR                             */
/*     WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH RESPECT TO PATENT RIGHTS                        */
/*     HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES) THAT MAY BE NECESSARY TO IMPLEMENT                            */
/*     THIS SPECIFICATION OR OTHERWISE. Contact TCG Administration                                                */
/*     (admin@trustedcomputinggroup.org) for information on specification licensing rights available              */
/*     through TCG membership agreements.                                                                         */
/*     THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                               */
/*     WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A                                     */
/*     PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF INTELLECTUAL                             */
/*     PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF ANY PROPOSAL,                                    */
/*     SPECIFICATION OR SAMPLE.                                                                                   */
/*     Without limitation, TCG and its members and licensors disclaim all liability, including liability for      */
/*     infringement of any proprietary rights, relating to use of information in this specification and to        */
/*     the implementation of this specification, and TCG disclaims all liability for cost of procurement          */
/*     of substitute goods or services, lost profits, loss of use, loss of data or any incidental,                */
/*     consequential, direct, indirect, or special damages, whether under contract, tort, warranty or             */
/*     otherwise, arising in any way out of use or reliance upon this specification or any information            */
/*     herein.                                                                                                    */
/*     Any marks and brands contained herein are the property of their respective owner.                          */
/*                                                                                                                */
/******************************************************************************************************************/

#ifndef _TPM_BUILD_SWITCHES_H
#define _TPM_BUILD_SWITCHES_H
#define SIMULATION
#define FIPS_COMPLIANT
#if defined(_Win32) || defined(WIN32)
#define ALIGN_TO(boundary) __declspec(align(boundary))
#else
#define ALIGN_TO(boundary) __attribute__ ((aligned (boundary)))
#endif
// #define ALIGN_TO(boundary) _Alignas(boundary)
#undef _DRBG_STATE_SAVE
#define _DRBG_STATE_SAVE        // Comment this out if no state save is wanted
#ifdef CRYPTO_ALIGN_16
# define CRYPTO_ALIGNMENT 16
#elif defined CRYPTO_ALIGN_8
# define CRYPTO_ALIGNMENT 8
#eliF defined CRYPTO_ALIGN_2
# define CRYPTO_ALIGNMENT 2
#elif defined CRTYPO_ALIGN_1
# define CRYPTO_ALIGNMENT 1
#else
# define CRYPTO_ALIGNMENT 4      // For 32-bit builds
#endif
#define CRYPTO_ALIGNED ALIGN_TO(CRYPTO_ALIGNMENT)
#if defined(_Win32) || defined(WIN32)
#define LIB_EXPORT __declspec(dllexport)
// #define LIB_EXPORT
#else 
//#define LIB_EXPORT __declspec(dllexport)
#define LIB_EXPORT
#endif
#define LIB_IMPORT __declspec(dllimport)
//#define LIB_IMPORT
#define _No_Return_ __declspec(noreturn)
//#define _No_Return_
#ifdef SELF_TEST
#pragma comment(lib, "algorithmtests.lib")
#endif
#ifdef SIMULATION
# define RSA_KEY_CACHE
# define TPM_RNG_FOR_DEBUG
#else
# undef RSA_KEY_CACHE
# undef TPM_RNG_FOR_DEBUG
#endif    // SIMULATION
#define INLINE __inline
#endif    // _TPM_BUILD_SWITCHES_H
