/* eslint-disable react/jsx-curly-newline */
import React, { useState, useEffect, useReducer, useCallback } from 'react';
import PropTypes from 'prop-types';
import { makeStyles } from '@material-ui/core/styles';
import KeyboardReturnIcon from '@material-ui/icons/KeyboardReturn';
import { useHistory } from 'react-router-dom';
import Modal from '@material-ui/core/Modal';
import { Backdrop, Typography, InputLabel } from '@material-ui/core';
import Tooltip from '@material-ui/core/Tooltip';
import { useMatomo } from '@datapunt/matomo-tracker-react';
import Fade from '@material-ui/core/Fade';
import styled, { css } from 'styled-components';
import useMediaQuery from '@material-ui/core/useMediaQuery';
import TextFieldComponent from '../../../../components/FormFields/TextField';
import ButtonComponent from '../../../../components/FormFields/ActionButton';
import infoIcon from '../../../../assets/info.svg';
import removeIcon from '../../../../assets/close.svg';
import ComponentError from '../../../../errorBoundaries/ComponentError/component-error';
import ApproleIcon from '../../../../assets/icon-approle.svg';
import leftArrowIcon from '../../../../assets/left-arrow.svg';
import mediaBreakpoints from '../../../../breakpoints';
import SnackbarComponent from '../../../../components/Snackbar';
import { useStateValue } from '../../../../contexts/globalState';
import BackdropLoader from '../../../../components/Loaders/BackdropLoader';
import apiService from '../apiService';
import { debounce } from 'lodash';
import TypeAheadComponent from '../../../../components/TypeAheadComponent';
import LoaderSpinner from '../../../../components/Loaders/LoaderSpinner';
import {
  GlobalModalWrapper,
  RequiredCircle,
  RequiredText,
  InstructionText,
  TitleThree,
} from '../../../../styles/GlobalStyles';

const { small } = mediaBreakpoints;

const StyledModal = styled(Modal)`
  @-moz-document url-prefix() {
    .MuiBackdrop-root {
      position: absolute;
      height: 115rem;
    }
  }
`;

const HeaderWrapper = styled.div`
  display: flex;
  align-items: center;
  ${small} {
    margin-top: 1rem;
  }
`;

const LeftIcon = styled.img`
  display: none;
  ${small} {
    display: block;
    margin-right: 1.4rem;
    margin-top: 0.3rem;
  }
`;
const IconDescriptionWrapper = styled.div`
  display: flex;
  align-items: center;
  margin-bottom: 0.5rem;
  position: relative;
  margin-top: 3.2rem;
`;

const SafeIcon = styled.img`
  height: 5.7rem;
  width: 5rem;
  margin-right: 2rem;
`;

const extraCss = css`
  ${small} {
    font-size: 1.3rem;
  }
`;

const CreateSafeForm = styled.form`
  display: flex;
  flex-direction: column;
  margin-top: 2.8rem;
`;

const InputFieldLabelWrapper = styled.div`
  margin-bottom: 2rem;
  position: ${(props) => (props.postion ? 'relative' : '')};
  .MuiSelect-icon {
    top: auto;
    color: #000;
  }
`;

const CancelSaveWrapper = styled.div`
  display: flex;
  justify-content: flex-end;
  ${small} {
    margin-top: 5.3rem;
  }
  button {
    ${small} {
      height: 4.5rem;
    }
  }
`;

const CancelButton = styled.div`
  margin-right: 0.8rem;
  ${small} {
    margin-right: 1rem;
    width: 100%;
  }
`;

const TransferButton = styled.div`
  margin-right: 0.8rem;
  ${small} {
    margin-right: 1rem;
    width: 100%;
  }
`;

const TransferConfirmButton = styled.div`
  margin-top: 2rem;
`;

const InputLabelWrap = styled.div`
  display: flex;
  justify-content: space-between;
`;

const InfoIcon = styled('img')``;
const RequiredInfo = styled.div`
  display: flex;
  align-items: center;
  justify-content: flex-end;
`;
const Span = styled('span')`
  font-size: 1.3rem;
  color: #29bd51;
`;

const InputLabelWithInfo = styled(InputLabel)`
  cursor: pointer;
`;

const EndingBox = styled.div`
  background-color: ${(props) =>
    props.theme.customColor.primary.backgroundColor};
  color: ${(props) => props.theme.customColor.primary.color};
  width: ${(props) => props.width};
  display: flex;
  align-items: center;
  height: 5rem;
`;

const ReturnIcon = styled.span`
  margin-left: auto;
  margin-right: 1rem;
  margin-top: 0.5rem;
  cursor: pointer;
`;

const ArrayList = styled.div`
  display: flex;
  flex-wrap: wrap;
  margin-top: 1rem;
`;

const RemoveIcon = styled.img`
  width: 1.5rem;
  margin-left: 1rem;
  cursor: pointer;
`;

const EachItem = styled.div`
  background-color: #454c5e;
  padding: 1rem;
  display: flex;
  align-items: center;
  margin: 0.3rem 0.5rem 0.3rem 0;
`;

const Name = styled.span`
  font-size: 1.4rem;
`;

const SharedToAutoWrap = styled.div`
  display: flex;
`;

const AutoInputFieldLabelWrapper = styled.div`
  position: relative;
  width: 100%;
  display: flex;
  .MuiTextField-root {
    width: 100%;
  }
`;

const autoLoaderStyle = css`
  position: absolute;
  top: 1rem;
  right: 4rem;
`;

const TypeAheadWrap = styled.div`
  width: 100%;
`;

const EachValueWrap = styled.div`
  display: flex;
  font-size: 1.4rem;
  margin: 0 0 2rem 0;
  p {
    margin: 0;
  }
`;
const Label = styled.p`
  color: ${(props) => props?.theme?.customColor?.label?.color};
  margin-right: 0.5rem !important;
`;

const Value = styled.p`
  text-transform: ${(props) => props.capitalize || ''};
`;

const useStyles = makeStyles((theme) => ({
  modal: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    overflowY: 'auto',
    padding: '10rem 0',
    [theme.breakpoints.down('xs')]: {
      alignItems: 'unset',
      justifyContent: 'unset',
      padding: '0',
      height: '100%',
    },
  },
}));

const useTooltipStyles = makeStyles((theme) => ({
  arrow: {
    color: theme.palette.common.white,
  },
  tooltip: {
    backgroundColor: theme.palette.common.white,
    color: theme.palette.common.black,
    fontSize: theme.typography.subtitle2.fontSize,
  },
}));

const CreateAppRole = (props) => {
  const { refresh } = props;
  const classes = useStyles();
  const tooltipClasses = useTooltipStyles();
  const [open, setOpen] = useState(true);
  const [responseType, setResponseType] = useState(null);
  const isMobileScreen = useMediaQuery(small);
  const [appRoleError, setApproleError] = useState(null);
  const [editApprole, setEditApprole] = useState(false);
  const [allAppRoles, setAllAppRoles] = useState([]);
  const [nameAvailable, setNameAvailable] = useState(true);
  const [status, setStatus] = useState({});
  const history = useHistory();
  const [stateVal] = useStateValue();
  const { trackPageView, trackEvent } = useMatomo();
  const [sharedToArray, setSharedToArray] = useState([]);
  const [sharedTo, setSharedTo] = useState('');
  const [sharedToError, setSharedToError] = useState(false);
  const [sharedToErrorMessage, setSharedToErrorMessage] = useState('');
  const [canEditSharedTo, setCanEditSharedTo] = useState(true);
  const [options, setOptions] = useState([]);
  const [autoLoader, setAutoLoader] = useState(false);
  const [sharedToUserSelected, setSharedToUserSelected] = useState(false);
  const [openTransferConfirmationModal, setOpenTransferConfirmationModal] = useState(false);
  const [newOwnerEmail, setNewOwnerEmail] = useState('');
  const [newOwnerNTID, setNewOwnerNTID] = useState('');
  const [newOwnerSelected, setNewOwnerSelected] = useState(false);
  const [transferError, setTransferError] = useState(false);
  const [transferErrorMessage, setTransferErrorMessage] = useState('');
  const [appRoleOwner, setAppRoleOwner] = useState('');

  const admin = Boolean(stateVal.isAdmin);

  const initialState = {
    roleName: '',
    maxTokenTtl: '',
    tokenTtl: '',
    sectetIdNumUses: '',
    tokenNumUses: '',
    secretIdTtl: '',
    tokenPolicies: '',
  };
  // eslint-disable-next-line consistent-return
  const reducer = (state, { field, type, value, payload }) => {
    switch (type) {
      case 'INPUT_FORM_FIELDS':
        return { ...state, [field]: value };

      case 'UPDATE_FORM_FIELDS':
        return { ...state, ...payload };

      default:
        break;
    }
  };
  const [state, dispatch] = useReducer(reducer, initialState);

  const onChange = (e) => {
    dispatch({
      type: 'INPUT_FORM_FIELDS',
      field: e?.target?.name,
      value: e?.target?.value.toLowerCase(),
    });
  };
  const {
    roleName,
    maxTokenTtl,
    tokenTtl,
    sectetIdNumUses,
    tokenNumUses,
    secretIdTtl,
    tokenPolicies,
  } = state;

  useEffect(() => {
    setStatus({ status: 'loading' });
    apiService
      .getAppRole()
      .then((res) => {
        setStatus({});
        const appRolesArr = [];
        if (res?.data?.keys) {
          res.data.keys.map((item) => {
            const appObj = {
              name: item,
              admin,
            };
            return appRolesArr.push(appObj);
          });
        }
        setAllAppRoles([...appRolesArr]);
      })
      .catch(() => {
        setStatus({});
      });
  }, [admin]);

  useEffect(() => {
    if (history.location.pathname === '/vault-app-roles/edit-vault-app-role' &&
        history.location.state.appRoleDetails.isEdit) {
      getAppRoleOwner().then((ownerInfo) => {
        if (ownerInfo.length > 0) {
          setCanEditSharedTo(ownerInfo[0] == stateVal.username);
          setAppRoleOwner(ownerInfo[1]);
        }
      })
    }
  }, [canEditSharedTo]);

  const handleClose = () => {
    setOpen(false);
    history.goBack();
  };

  const handleTransferClose = () => {
    setNewOwnerEmail('');
    setNewOwnerSelected(false);
    setOpen(true);
    setOpenTransferConfirmationModal(false);
  };

  /**
   * @function validateRoleName
   * @description To check the existing rolenames
   * @param {*} e event of input handler
   */

  const validateRoleName = (name) => {
    const itemExits = allAppRoles?.filter((approle) => approle.name === name);
    if (itemExits?.length) {
      setApproleError({
        error: true,
        message: 'This approle name already exists, Please take another name.',
      });
      setNameAvailable(false);
      return;
    }
    if (name.length < 3 || !name.match(/^[A-Za-z0-9_]*?[a-z0-9]$/i)) {
      setApproleError({ error: true, message: 'Please enter valid role name' });
      setNameAvailable(false);
      return;
    }
    setApproleError({ error: false });
    setNameAvailable(true);
  };

  const getAppRoleOwner = () => {
    return new Promise((resolve, reject) =>
      apiService
        .getAppRoleOwner(history.location.state.appRoleDetails.name)
        .then((res) => {
          resolve(res.data);
        })
        .catch((err) => {
          if (err.response && err.response.data?.errors[0]) {
            setStatus({ status: 'failed', message: err.response.data.errors[0] });
          }
          setResponseType(-1);
          reject(err.data);
        })
    );
  };

  const onRoleNameChange = (e) => {
    setApproleError(false);
    validateRoleName(e.target.value.toLowerCase());
    onChange(e);
  };

  const onInputNumberChange = (e) => {
    const re = /^[0-9\b]+$/;
    if (e.target.value <= 999999999) {
      if (e?.target?.value === '' || re.test(e?.target?.value)) {
        onChange(e);
      }
    }
  };

  const onAddSharedToEnterClicked = (e) => {
    if (e.keyCode === 13 && e?.target?.value) {
      e.preventDefault();
      onAddSharedToKeyClicked();
    }
  };

  const onAddSharedToKeyClicked = () => {
    if (sharedTo && !sharedToError && sharedToUserSelected) {
      if (!checkSharedToAlreadyIncluded(sharedTo)) {
        setSharedToArray((prev) => [...prev, sharedTo.toLowerCase()]);
        setSharedTo('');
        setSharedToError(false);
        setSharedToErrorMessage('');
      }
    }
  };

  const checkSharedToAlreadyIncluded = (val) => {
    let alreadyContains = false;
    if (sharedToArray?.includes(val)) {
      setSharedToError(true);
      setSharedToErrorMessage('Name already added!');
      alreadyContains = true;
    }
    return alreadyContains;
  };

  const onSharedToChange = (e) => {
    setSharedTo(e.target.value);
    setSharedToUserSelected(false);
    callSearchApi(e.target.value);
    setSharedToError(false);
    setSharedToErrorMessage('');
  };

  const onNewOwnerChange = (e) => {
    setNewOwnerEmail(e.target.value);
    setNewOwnerSelected(false);
    callSearchApi(e.target.value);
    setTransferError(false);
    setTransferErrorMessage('');
  };

  const onRemoveClicked = (sharedTo) => {
    if (canEditSharedTo) {
      const array = sharedToArray.filter((item) => item !== sharedTo);
      setSharedToArray([...array]);
    }
  };

  const onTransferKeyClicked = (e) => {
    if (e.keyCode === 13 && e?.target?.value) {
      e.preventDefault();
    }
  }

  const splitString = (val) => {
    return val.split('_').slice('2').join('_');
  };

  const handleTransferModalClose = () => {
    setOpenTransferConfirmationModal(false); 
    handleClose();
  }

  useEffect(() => {
    if (
      history.location.pathname === '/vault-app-roles/edit-vault-app-role' &&
      history.location.state.appRoleDetails.isEdit
    ) {
      setEditApprole(true);
      setResponseType(0);
      setAllAppRoles([...history.location.state.appRoleDetails.allAppRoles]);
      apiService
        .fetchAppRole(history.location.state.appRoleDetails.name)
        .then((res) => {
          setResponseType(null);
          if (res?.data?.data) {
            const array = [];
            if (
              res?.data?.data?.token_policies &&
              res?.data?.data?.token_policies?.length > 0
            ) {
              res.data.data.token_policies.map((item) => {
                const str = splitString(item);
                return array.push(str);
              });
            }
            if (res.data.data.shared_to != null) {
              setSharedToArray(res.data.data.shared_to);
            } else {
              setSharedToArray([]);
            }
            dispatch({
              type: 'UPDATE_FORM_FIELDS',
              payload: {
                roleName: history.location.state.appRoleDetails.name,
                maxTokenTtl: res.data.data.token_max_ttl,
                tokenTtl: res.data.data.token_ttl,
                sectetIdNumUses: res.data.data.secret_id_num_uses,
                tokenNumUses: res.data.data.token_num_uses,
                secretIdTtl: res.data.data.secret_id_ttl,
                sharedToArray: res.data.data.shared_to,
                tokenPolicies: array.join(','),
              },
            });
          }
        })
        .catch((err) => {
          if (err.response && err.response.data?.errors[0]) {
            setStatus({ message: err.response.data.errors[0] });
          }
          setResponseType(-1);
        });

    }
  }, [history]);

  const constructPayload = () => {
    const data = {
      role_name: roleName,
      secret_id_num_uses: sectetIdNumUses,
      secret_id_ttl: secretIdTtl,
      token_max_ttl: maxTokenTtl,
      token_num_uses: tokenNumUses,
      token_ttl: tokenTtl,
      shared_to: sharedToArray,
    };

    return data;
  };

  const onEditApprole = () => {
    const payload = constructPayload();
    setResponseType(0);
    apiService
      .updateAppRole(payload)
      .then(async (res) => {
        if (res) {
          setResponseType(1);
          setStatus({ status: 'success', message: res.data.messages[0] });
          await refresh();
          setTimeout(() => {
            setOpen(false);
            history.goBack();
          }, 1000);
        }
      })
      .catch((err) => {
        if (err.response && err.response?.data?.errors) {
          setStatus({ status: 'failed', message: err.response.data.errors[0] });
        }
      
        setResponseType(-1);
      });
  };

  const onTransferAppRoleOwner = () => {
    const payload = {
      new_owner_email: newOwnerEmail,
      owner: newOwnerNTID,
      role_name: roleName
    }
    setResponseType(0);
    apiService
      .updateAppRole(payload)
      .then(async (res) => {
        if (res) {
          setResponseType(1);
          setStatus({ status: 'success', message: res.data.messages[0] });
          await refresh();
          setTimeout(() => {
            setOpen(false);
            history.goBack();
          }, 1000);
        }
      })
      .catch((err) => {
        if (err.response && err.response?.data?.errors) {
          setStatus({ status: 'failed', message: err.response.data.errors[0] });
        }
      
        setResponseType(-1);
      });
  };

  useEffect(() => {
    trackPageView();
    return () => {
      trackPageView();
    };
  }, [trackPageView]);

  const onCreateApprole = () => {
    const payload = constructPayload();
    setResponseType(0);
    apiService
      .createAppRole(payload)
      .then(async (res) => {
        if (res) {
          setResponseType(1);
          trackEvent({
            category: 'vault-approle-creation',
            action: 'click-event',
          });
          setStatus({ status: 'success', message: res.data.messages[0] });
          await refresh();
          setTimeout(() => {
            setOpen(false);
            history.goBack();
          }, 1000);
        }
      })
      .catch((err) => {
        if (err.response && err.response.data?.errors) {
          setStatus({ status: 'failed', message: err.response.data.errors[0] });
        }
        setResponseType(-1);
      });
  };

  const onToastClose = (reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setResponseType(null);
    setStatus({});
  };

  const onSelected = (e, val) => {
    const splitValues = val?.split(', ');
    const sharedToUserNTID = (splitValues[0].toLowerCase().includes('@sprint.com')) ? splitValues[1] : splitValues[2];
    setSharedToUserSelected(true);
    setSharedTo(sharedToUserNTID);
  };

  const onNewOwnerSelected = (e, val) => {
    const splitValues = val?.split(', ');
    const newOwnerUserNTID = (splitValues[0].toLowerCase().includes('@sprint.com')) ? splitValues[1] : splitValues[2];
    const newOwnerEmailAddress = splitValues[0];
    setNewOwnerSelected(true);
    setNewOwnerEmail(newOwnerEmailAddress);
    setNewOwnerNTID(newOwnerUserNTID);
  }

  const callSearchApi = useCallback(
    debounce(
      (value) => {
        setAutoLoader(true);
        const userNameSearch = apiService.getUserName(value);
        const tmoUser = apiService.getTmoUsers(value);
        Promise.all([userNameSearch, tmoUser])
          .then((responses) => {
            setOptions([]);
            const array = new Set([]);
            if (responses[0]?.data?.data?.values?.length > 0) {
              responses[0].data.data.values.map((item) => {
                if (item.userName) {
                  return array.add(item);
                }
                return null;
              });
            }
            if (responses[1]?.data?.data?.values?.length > 0) {
              responses[1].data.data.values.map((item) => {
                if (item.userName) {
                  return array.add(item);
                }
                return null;
              });
            }
            setOptions([...array]);
            setAutoLoader(false);
          })
          .catch(() => {
            setAutoLoader(false);
          });
      },
      1000,
      true
    ),
    []
  );

  const getName = (displayName) => {
    if (displayName?.match(/(.*)\[(.*)\]/)) {
      const lastFirstName = displayName?.match(/(.*)\[(.*)\]/)[1].split(', ');
      const name = `${lastFirstName[1]} ${lastFirstName[0]}`;
      const optionalDetail = displayName?.match(/(.*)\[(.*)\]/)[2];
      return `${name}, ${optionalDetail}`;
    }
    if (displayName?.match(/(.*), (.*)/)) {
      const lastFirstName = displayName?.split(', ');
      const name = `${lastFirstName[1]} ${lastFirstName[0]}`;
      return name;
    }
    return displayName;
  };

  const getDisabledState = () => {
    return (
      roleName === '' ||
      maxTokenTtl === '' ||
      tokenTtl === '' ||
      sectetIdNumUses === '' ||
      tokenNumUses === '' ||
      secretIdTtl === '' ||
      appRoleError?.error
    );
  };
  return (
    <ComponentError>
      {!openTransferConfirmationModal && (<StyledModal
        aria-labelledby="transition-modal-title"
        aria-describedby="transition-modal-description"
        className={classes.modal}
        open={open}
        onClose={() => handleClose()}
        closeAfterTransition
        BackdropComponent={Backdrop}
        BackdropProps={{
          timeout: 500,
        }}
      >
        <Fade in={open}>
          <GlobalModalWrapper>
            {responseType === 0 && <BackdropLoader />}
            <HeaderWrapper>
              <LeftIcon
                src={leftArrowIcon}
                alt="go-back"
                onClick={() => handleClose()}
              />
              <Typography variant="h5">
                {editApprole ? 'Edit AppRole' : 'Create AppRole'}
              </Typography>
            </HeaderWrapper>
            <IconDescriptionWrapper>
              <SafeIcon src={ApproleIcon} alt="app-role-icon" />
              <TitleThree lineHeight="1.8rem" extraCss={extraCss} color="#ccc">
                Approles operate a lot like safes, but they put the
                application at the logical unit for sharing.
              </TitleThree>
            </IconDescriptionWrapper>
            <CreateSafeForm>
              <RequiredInfo>
                <RequiredCircle />
                <RequiredText>Required</RequiredText>
              </RequiredInfo>
              <InputFieldLabelWrapper>
                <InputLabelWrap>
                  <InputLabel>
                    Role Name
                    <RequiredCircle margin="0.5rem" />
                  </InputLabel>

                  <InfoIcon src={infoIcon} alt="info-icon-role-name" />
                </InputLabelWrap>
                <TextFieldComponent
                  value={roleName}
                  placeholder="Role name - enter minimum 3 characters"
                  fullWidth
                  readOnly={!!editApprole}
                  characterLimit={50}
                  name="roleName"
                  onChange={(e) => onRoleNameChange(e)}
                  error={appRoleError?.error}
                  helperText={appRoleError?.message || ''}
                />

                {roleName && nameAvailable && !editApprole && (
                  <Span>Role Name Available!</Span>
                )}
              </InputFieldLabelWrapper>
              {editApprole && (
              <>
                <InputFieldLabelWrapper>
                  <InputLabelWrap>
                    <InputLabel>
                      Role Owner
                      <RequiredCircle margin="0.5rem" />
                    </InputLabel>
                    <InfoIcon src={infoIcon} alt="info-icon-role-name" />
                  </InputLabelWrap>
                  <TextFieldComponent
                    value={appRoleOwner}
                    placeholder="Role name - enter minimum 3 characters"
                    fullWidth
                    readOnly={true}
                    characterLimit={50}
                    name="roleName"
                    onChange={(e) => onRoleNameChange(e)}
                    error={appRoleError?.error}
                    helperText={appRoleError?.message || ''}
                  />
                  {roleName && nameAvailable && !editApprole && (
                    <Span>Role Name Available!</Span>
                  )}
                </InputFieldLabelWrapper>
              </>
              )}
              <Tooltip
                classes={tooltipClasses}
                arrow
                title="Duration in seconds after which the issued token can no longer be renewed"
                placement="top"
              >
                <InputFieldLabelWrapper postion>
                  <InputLabelWrap>
                    <InputLabelWithInfo>
                      Token Max TTL
                      <RequiredCircle margin="0.5rem" />
                    </InputLabelWithInfo>
                    <InfoIcon src={infoIcon} alt="info-icon" />
                  </InputLabelWrap>

                  <TextFieldComponent
                    value={maxTokenTtl}
                    placeholder="Token Max TTL"
                    fullWidth
                    name="maxTokenTtl"
                    onChange={(e) => onInputNumberChange(e)}
                  />
                </InputFieldLabelWrapper>
              </Tooltip>
              <Tooltip
                classes={tooltipClasses}
                arrow
                title="Duration in seconds to set as a TTL for issued tokens and at renewal time"
                placement="top"
              >
                <InputFieldLabelWrapper>
                  <InputLabelWrap>
                    <InputLabelWithInfo>
                      Token TTL
                      <RequiredCircle margin="0.5rem" />
                    </InputLabelWithInfo>
                    <InfoIcon src={infoIcon} alt="info-icon-token" />
                  </InputLabelWrap>

                  <TextFieldComponent
                    value={tokenTtl}
                    placeholder="Token_TTL"
                    fullWidth
                    name="tokenTtl"
                    onChange={(e) => onInputNumberChange(e)}
                  />
                </InputFieldLabelWrapper>
              </Tooltip>
              <Tooltip
                classes={tooltipClasses}
                arrow
                title="Number of times the secretID can be used to fetch a token from this approle"
                placement="top"
              >
                <InputFieldLabelWrapper>
                  <InputLabelWrap>
                    <InputLabelWithInfo>
                      Secret ID Number Uses
                      <RequiredCircle margin="0.5rem" />
                    </InputLabelWithInfo>
                    <InfoIcon src={infoIcon} alt="info-icon-sec" />
                  </InputLabelWrap>

                  <TextFieldComponent
                    value={sectetIdNumUses}
                    placeholder="secret_Id_Num_Uses"
                    fullWidth
                    name="sectetIdNumUses"
                    onChange={(e) => onInputNumberChange(e)}
                  />
                </InputFieldLabelWrapper>
              </Tooltip>
              <Tooltip
                classes={tooltipClasses}
                arrow
                title="Number of times the issued token can be used"
                placement="top"
              >
                <InputFieldLabelWrapper>
                  <InputLabelWrap>
                    <InputLabelWithInfo>
                      Token Number Uses
                      <RequiredCircle margin="0.5rem" />
                    </InputLabelWithInfo>

                    <InfoIcon src={infoIcon} alt="info-icon-token-uses" />
                  </InputLabelWrap>
                  <TextFieldComponent
                    value={tokenNumUses}
                    placeholder="token_num_uses"
                    fullWidth
                    name="tokenNumUses"
                    onChange={(e) => onInputNumberChange(e)}
                  />
                </InputFieldLabelWrapper>
              </Tooltip>
              <Tooltip
                classes={tooltipClasses}
                arrow
                title="Duration in seconds after which the issued secretID expires"
                placement="top"
              >
                <InputFieldLabelWrapper>
                  <InputLabelWrap>
                    <InputLabelWithInfo>
                      Secret ID TTL
                      <RequiredCircle margin="0.5rem" />
                    </InputLabelWithInfo>
                    <InfoIcon src={infoIcon} alt="info-icon-secret-id" />
                  </InputLabelWrap>
                  <TextFieldComponent
                    value={secretIdTtl}
                    placeholder="secret_id_ttl"
                    fullWidth
                    name="secretIdTtl"
                    onChange={(e) => onInputNumberChange(e)}
                  />
                </InputFieldLabelWrapper>
              </Tooltip>
              <InputFieldLabelWrapper>
                <>
                  <Tooltip
                    classes={tooltipClasses}
                    arrow
                    title="Shared To List"
                    placement="top"
                  >
                    <InputLabel>
                      Add Users to Share This AppRole With
                    </InputLabel>
                  </Tooltip>
                </>   
                <SharedToAutoWrap>
                  <AutoInputFieldLabelWrapper>
                    <TypeAheadWrap>
                      <TypeAheadComponent
                        options = { 
                          options.map(
                            (item) =>
                              `${item?.userEmail?.toLowerCase()}, ${
                                item?.displayName &&
                                item?.displayName !== '' &&
                                getName(item?.displayName?.toLowerCase()) !== ' '
                                  ? `${getName(item?.displayName?.toLowerCase())}, `: ''
                              }${item?.userName?.toLowerCase()}`
                          )
                          }
                        loader={autoLoader}
                        userInput={sharedTo}
                        icon="search"
                        name="notifyUser"
                        onSelected={(e, val) => onSelected(e, val)}
                        onKeyDownClick={(e) => onAddSharedToEnterClicked(e)}
                        onChange={(e) => {
                          onSharedToChange(e);
                        }}
                        placeholder={'Search by NTID, Email or Name'}
                        error={sharedToError}
                        helperText={
                          sharedToError ? sharedToErrorMessage : ''
                        }
                        disabled={!canEditSharedTo}
                        styling={{ bottom: '5rem' }}
                      />
                      {autoLoader && sharedTo.length > 2 && (
                        <LoaderSpinner customStyle={autoLoaderStyle} />
                      )}
                    </TypeAheadWrap>
                    {canEditSharedTo && (
                      <EndingBox width="4rem">
                        <ReturnIcon onClick={() => onAddSharedToKeyClicked()}>
                          <KeyboardReturnIcon />
                        </ReturnIcon>
                      </EndingBox>
                    )}
                  </AutoInputFieldLabelWrapper>
                </SharedToAutoWrap>
                <ArrayList>
                  {sharedToArray.map((item) => {
                    return (
                      <EachItem key={item}>
                        <Name>{item}</Name>
                        {canEditSharedTo && (
                          <RemoveIcon
                            src={removeIcon}
                            alt="remove"
                            onClick={() => onRemoveClicked(item)}
                          />
                        )}
                      </EachItem>
                    );
                  })}
                </ArrayList>
              </InputFieldLabelWrapper>  
            </CreateSafeForm>
            <CancelSaveWrapper>
              <CancelButton>
                <ButtonComponent
                  label="Cancel"
                  color="primary"
                  onClick={() => handleClose()}
                  width={isMobileScreen ? '100%' : ''}
                />
              </CancelButton>
              <TransferButton>
                {editApprole && (<ButtonComponent
                  label='Transfer'
                  color='secondary'
                  disabled={!canEditSharedTo && !admin}
                  onClick={() => setOpenTransferConfirmationModal(true)}
                  width={isMobileScreen ? '100%' : ''}
                />)}
              </TransferButton>
              <ButtonComponent
                label={!editApprole ? 'Create' : 'Update'}
                color="secondary"
                icon={!editApprole ? 'add' : ''}
                disabled={getDisabledState()}
                onClick={() =>
                  !editApprole ? onCreateApprole() : onEditApprole()
                }
                width={isMobileScreen ? '100%' : ''}
              />
            </CancelSaveWrapper>
            {status.status === 'failed' && (
              <SnackbarComponent
                open
                onClose={() => onToastClose()}
                severity="error"
                icon="error"
                message={status.message || 'Something went wrong!'}
              />
            )}
            {status.status === 'success' && (
              <SnackbarComponent
                open
                onClose={() => onToastClose()}
                message={
                  status.message || 'Approle has been created successfully '
                }
              />
            )}
          </GlobalModalWrapper>
        </Fade>
      </StyledModal>)}
      <StyledModal
        aria-labelledby="transition-modal-title"
        aria-describedby="transition-modal-description"
        className={classes.modal}
        open={openTransferConfirmationModal}
        onClose={() => handleTransferModalClose()}
        closeAfterTransition
        BackdropComponent={Backdrop}
        BackdropProps={{
          timeout: 500,
        }}
      >
        <Fade in={openTransferConfirmationModal}>
          <GlobalModalWrapper>
            {responseType === 0 && <BackdropLoader />}
              <HeaderWrapper>
                <LeftIcon
                  src={leftArrowIcon}
                  alt="go-back"
                  onClick={() => handleClose()}
                />
                <Typography variant="h5">
                  Transfer AppRole Owner
                </Typography>
              </HeaderWrapper>
              <CreateSafeForm>
              <EachValueWrap>
                  <Label>AppRole Name:</Label>
                  <Value>{history.location.state?.appRoleDetails?.name}</Value>
              </EachValueWrap>
              <EachValueWrap>
                  <Label>Current Owner:</Label>
                  <Value>{appRoleOwner}</Value>
              </EachValueWrap>
              <InputFieldLabelWrapper>
                <>
                  <Tooltip
                    classes={tooltipClasses}
                    arrow
                    title="New Owner of the AppRole"
                    placement="top"
                  >
                    <InputLabelWithInfo>
                      New Owner
                      <RequiredCircle margin="0.5rem" />
                    </InputLabelWithInfo>
                  </Tooltip>
                </>
                <SharedToAutoWrap>
                  <AutoInputFieldLabelWrapper>
                    <TypeAheadWrap>
                      <TypeAheadComponent
                        options = { 
                          options.map(
                            (item) =>
                              `${item?.userEmail?.toLowerCase()}, ${
                                item?.displayName &&
                                item?.displayName !== '' &&
                                getName(item?.displayName?.toLowerCase()) !== ' '
                                  ? `${getName(item?.displayName?.toLowerCase())}, `: ''
                              }${item?.userName?.toLowerCase()}`
                          )
                          }
                        loader={autoLoader}
                        userInput={newOwnerEmail}
                        icon="search"
                        name="newOwner"
                        onSelected={(e, val) => onNewOwnerSelected(e, val)}
                        onChange={(e) => {
                          onNewOwnerChange(e);
                        }}
                        onKeyDownClick={(e) => onTransferKeyClicked(e)}
                        placeholder={'Search by NTID, Email or Name'}
                        error={transferError}
                        helperText={transferError ? transferErrorMessage : ''}
                        disabled={!canEditSharedTo && !admin}
                        styling={{ bottom: '5rem' }}
                      />
                      {autoLoader && sharedTo.length > 2 && (
                        <LoaderSpinner customStyle={autoLoaderStyle} />
                      )}
                    </TypeAheadWrap>
                  </AutoInputFieldLabelWrapper>
                </SharedToAutoWrap>
                <InstructionText>
                  Search the T-Mobile system to add users
                </InstructionText>
                <CancelSaveWrapper>
                  <CancelButton>
                    <ButtonComponent
                      label="Cancel"
                      color="primary"
                      onClick={() => handleTransferClose()}
                      width={isMobileScreen ? '100%' : ''}
                    />
                  </CancelButton>
                  <ButtonComponent 
                    label='Transfer'
                    color="secondary"
                    disabled={(!canEditSharedTo && !admin) || !newOwnerSelected}
                    onClick={() => onTransferAppRoleOwner()}
                    width={isMobileScreen ? '100%' : ''}
                  />
                </CancelSaveWrapper>
                {status.status === 'failed' && (
                  <SnackbarComponent
                    open
                    onClose={() => onToastClose()}
                    severity="error"
                    icon="error"
                    message={status.message || 'Something went wrong!'}
                  />
                )}
                {status.status === 'success' && (
                  <SnackbarComponent
                    open
                    onClose={() => onToastClose()}
                    message={
                      status.message || 'Approle has been created successfully '
                    }
                  />
                )}
              </InputFieldLabelWrapper>
            </CreateSafeForm>
          </GlobalModalWrapper>
        </Fade>
      </StyledModal>
    </ComponentError>
  );
};
CreateAppRole.propTypes = { refresh: PropTypes.func };
CreateAppRole.defaultProps = { refresh: () => {} };
export default CreateAppRole;
