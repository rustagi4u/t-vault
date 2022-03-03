/* eslint-disable no-nested-ternary */
import React, { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import useMediaQuery from '@material-ui/core/useMediaQuery';
import styled from 'styled-components';
import ComponentError from '../../../../../errorBoundaries/ComponentError/component-error';
import sectionHeaderBg from '../../../../../assets/Banner_img.png';
import sectionMobHeaderBg from '../../../../../assets/mob-safebg.svg';
import sectionTabHeaderBg from '../../../../../assets/tab-safebg.svg';
import mediaBreakpoints from '../../../../../breakpoints';
import ListDetailHeader from '../../../../../components/ListDetailHeader';
import ReactDOMServer from 'react-dom/server';

// styled components goes here
const Section = styled('section')`
  flex-direction: column;
  display: flex;
  z-index: 2;
  width: 100%;
  height: 100%;
`;

const SafeDetails = (props) => {
  const { detailData, resetClicked, renderContent } = props;
  const [safe, setSafe] = useState({});
  const isMobileScreen = useMediaQuery(mediaBreakpoints.small);
  const isTabScreen = useMediaQuery(mediaBreakpoints.medium);
  // route component data
  const goBackToSafeList = () => {
    resetClicked();
  };

  useEffect(() => {
    if (detailData && Object.keys(detailData).length > 0) {
      setSafe({ ...detailData });
    } else {
      setSafe({});
    }
  }, [detailData]);

  const AttentionAlert = styled('p')`
  color: #E20074;
  display: inline;
  font-weight: bold;
`;

  return (
    <ComponentError>
      <Section>
        <ListDetailHeader
          title={safe?.name || '...'}
          description={
            safe?.description ||
            `<span>${ReactDOMServer.renderToStaticMarkup(
              <AttentionAlert>ATTENTION: </AttentionAlert>) + 
                'Going forward users will not be able to create safes or secrets in T-Vault. Users will instead need to utilize either Enterprise Vault or CyberArk for their secret management needs. For information on how you can onboard your application into Enterprise Vault to begin creating secrets, please use the following <a style="color: #E20074;" href="https://confluencesw.t-mobile.com/display/ATPF/Onboarding" target="_blank">onboarding guide</a>.'
              }
            </span>`
              
          }
          bgImage={
            isMobileScreen
              ? sectionMobHeaderBg
              : isTabScreen
              ? sectionTabHeaderBg
              : sectionHeaderBg
          }
          goBackToList={goBackToSafeList}
        />
        {renderContent}
      </Section>
    </ComponentError>
  );
};
SafeDetails.propTypes = {
  detailData: PropTypes.objectOf(PropTypes.any),
  resetClicked: PropTypes.func,
  renderContent: PropTypes.node,
};
SafeDetails.defaultProps = {
  detailData: {},
  resetClicked: () => {},
  renderContent: <div />,
};

export default SafeDetails;
